"""Regression tests for the reusable workflow security contract."""

import re
from pathlib import Path

WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"


def _workflow_text() -> str:
    return "\n".join(p.read_text() for p in WORKFLOWS.glob("*.yml"))


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
