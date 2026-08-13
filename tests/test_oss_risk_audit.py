"""Contract tests for the deterministic CI/CD control audit."""

import json
from pathlib import Path

from legionforge_dev_rig.oss_risk_audit import Severity, run_all_checks


def _write_project(tmp_path: Path, workflow: str) -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(workflow)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    return tmp_path


def test_clean_workflow_has_no_high_findings(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        """name: CI
concurrency: {group: ci-${{ github.ref }}, cancel-in-progress: true}
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          persist-credentials: false
""",
    )
    result = run_all_checks(root)
    assert not [f for f in result.findings if f.severity == Severity.HIGH]


def test_unpinned_and_interpolated_inputs_are_detected(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        """name: CI
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: npm run ${{ inputs.test-script }}
""",
    )
    result = run_all_checks(root)
    risks = {f.risk for f in result.findings}
    assert "unpinned-action" in risks
    assert "template-injection" in risks
    assert "workflow-permissions" in risks
    assert "workflow-timeout" in risks


def test_config_can_explicitly_ignore_a_documented_risk(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        """name: CI
permissions: {contents: read}
concurrency: {group: ci, cancel-in-progress: true}
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@main
""",
    )
    config = {"ignore-risks": ["unpinned-action"]}
    result = run_all_checks(root, config)
    assert not any(f.risk == "unpinned-action" for f in result.findings)


def test_reusable_workflow_orchestrator_is_not_flagged_for_timeout(tmp_path: Path) -> None:
    # A job that only calls a reusable workflow (`uses: ./x.yml`, no
    # `runs-on:`) can't set timeout-minutes itself -- GitHub Actions rejects
    # that key there. Nothing runs directly on this file's own runner, so it
    # shouldn't be flagged for missing a timeout.
    root = _write_project(
        tmp_path,
        """name: CI (self-test)
permissions:
  contents: read
concurrency: {group: ci, cancel-in-progress: true}
jobs:
  lint:
    uses: ./.github/workflows/lint.yml
    with:
      source-dirs: "pkg"
""",
    )
    result = run_all_checks(root)
    risks = {f.risk for f in result.findings}
    assert "workflow-timeout" not in risks


def test_json_output_shape_is_serializable(tmp_path: Path) -> None:
    root = _write_project(tmp_path, "name: CI\n")
    result = run_all_checks(root)
    payload = {
        "findings": [f.__dict__ for f in result.findings],
        "inventory": result.inventory,
    }
    encoded = json.dumps(payload, default=str)
    assert "workflow_files" in encoded
