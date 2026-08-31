"""Regression tests for the reusable workflow security contract."""

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"
CI_TEMPLATES = Path(__file__).parents[1] / "examples" / "ci-templates"
PERMISSION_LEVELS = {"none": 0, "read": 1, "write": 2}
USES_RE = re.compile(r"LegionForge/dev-rig/\.github/workflows/([\w-]+\.yml)")


def _workflow_text() -> str:
    return "\n".join(p.read_text() for p in WORKFLOWS.glob("*.yml"))


def _permission_level(value: object) -> int:
    if value is True:
        return PERMISSION_LEVELS["write"]
    if value is False or value is None:
        return PERMISSION_LEVELS["none"]
    return PERMISSION_LEVELS.get(str(value), PERMISSION_LEVELS["none"])


def _merge_max(permission_dicts) -> dict[str, int]:
    merged: dict[str, int] = {}
    for perms in permission_dicts:
        for scope, value in (perms or {}).items():
            merged[scope] = max(merged.get(scope, 0), _permission_level(value))
    return merged


def _required_permissions_by_reusable_workflow() -> dict[str, dict[str, int]]:
    """For each reusable workflow, the permission ceiling its own jobs need.

    A caller's job-level `permissions:` on a `uses:` line fully REPLACES the
    workflow's top-level default rather than merging with it -- so a caller
    must grant at least the union of what every job inside the called
    workflow needs, or the whole thing fails at startup_failure (no job
    runs, so no check ever posts -- this is invisible on the PR itself).
    """
    required: dict[str, dict[str, int]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text())
        on = doc.get(True, doc.get("on", {}))
        if not isinstance(on, dict) or "workflow_call" not in on:
            continue  # not a reusable workflow (e.g. this repo's own self-test ci.yml)
        top_level = doc.get("permissions", {})
        job_perms = [job.get("permissions", top_level) for job in doc.get("jobs", {}).values()]
        required[path.name] = _merge_max(job_perms)
    return required


def _granted_permissions_by_template() -> dict[str, dict[str, dict[str, int]]]:
    """{template_file: {reusable_workflow_file: permissions granted to it}}"""
    granted: dict[str, dict[str, dict[str, int]]] = {}
    for path in sorted(CI_TEMPLATES.glob("*.yml")):
        doc = yaml.safe_load(path.read_text())
        top_level = doc.get("permissions", {})
        calls: dict[str, dict[str, int]] = {}
        for job in doc.get("jobs", {}).values():
            match = USES_RE.search(job.get("uses", ""))
            if match:
                calls[match.group(1)] = _merge_max([job.get("permissions", top_level)])
        granted[path.name] = calls
    return granted


def test_ci_templates_grant_what_reusable_workflows_require() -> None:
    """Guards against the exact bug that silently broke guardian/LegionForge/
    jeli/context-governor's CI for weeks: sast.yml's nested codeql job needs
    contents:read + security-events:write + actions:read, but every
    consumer's ci.yml only granted security-events:write. The mismatch
    causes startup_failure -- zero check runs posted, so branch-protection
    required-status-checks blocks every PR forever with no visible error.

    If a reusable workflow here starts requiring more than examples/ci-templates/
    grants, this test fails in dev-rig's own CI -- before that change ever
    reaches a real consumer repo.
    """
    required = _required_permissions_by_reusable_workflow()
    granted_by_template = _granted_permissions_by_template()
    assert granted_by_template, f"no CI templates found under {CI_TEMPLATES}"

    failures = []
    covered_workflows: set[str] = set()
    for template_name, calls in granted_by_template.items():
        for wf_file, granted in calls.items():
            covered_workflows.add(wf_file)
            for scope, need_level in required.get(wf_file, {}).items():
                have_level = granted.get(scope, 0)
                if have_level < need_level:
                    failures.append(
                        f"{template_name}: job calling {wf_file} grants "
                        f"{scope!r} at level {have_level} but the workflow "
                        f"needs level {need_level}"
                    )
    assert not failures, "\n".join(failures)

    # A reusable workflow that needs more than plain contents:read but isn't
    # exercised by any template can't be checked here -- flag the gap itself
    # rather than silently passing.
    baseline = {"contents": PERMISSION_LEVELS["read"]}
    uncovered = [
        wf for wf, need in required.items() if wf not in covered_workflows and need != baseline
    ]
    assert not uncovered, f"no CI template exercises these elevated-permission workflows: {uncovered}"


def test_all_actions_are_sha_pinned() -> None:
    pattern = re.compile(r"(?m)^\s*-?\s*uses:\s*[^\s#]+@([^\s#]+)")
    mutable = [
        ref
        for ref in pattern.findall(_workflow_text())
        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref)
    ]
    assert not mutable, f"mutable action references: {mutable}"


def test_workflows_have_bounded_least_privilege_jobs() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text()
        assert "permissions:" in text, path
        # A job that only calls a reusable workflow (`uses: ./x.yml`, no
        # `runs-on:`) can't set timeout-minutes itself -- GitHub Actions
        # rejects that key there. Nothing runs directly on such a file's own
        # runner, so it has no timeout to bound.
        if "runs-on:" in text:
            assert "timeout-minutes:" in text, path


def test_no_direct_workflow_input_shell_interpolation() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text()
        risky = re.findall(
            r"(?m)^\s+(?:pip\s+install|python\s+-m|npm\s+run|npx\s|semgrep\s|bandit\s|mypy\s|docker\s+run|cargo\s+audit).+\$\{\{\s*inputs\.",
            text,
        )
        assert not risky, f"unsafe input interpolation in {path}: {risky}"


def test_dast_and_trivy_fail_closed() -> None:
    dast = (WORKFLOWS / "dast.yml").read_text()
    trivy = (WORKFLOWS / "trivy.yml").read_text()
    assert "-J zap-report.json" in dast
    assert "zap-report.sarif" in dast
    assert 'default: "1"' in trivy
    assert "scan-type: image" in trivy
