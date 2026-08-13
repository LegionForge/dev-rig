"""Contract tests for the deterministic CI/CD control audit."""

import json
import sys
from pathlib import Path

import pytest
from legionforge_dev_rig.oss_risk_audit import (
    AuditResult,
    Finding,
    Severity,
    _format_text_output,
    main,
    run_all_checks,
)


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


def test_silent_failure_is_flagged(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        """name: CI
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: flaky-tool
        continue-on-error: true
""",
    )
    result = run_all_checks(root)
    assert any(f.risk == "silent-failure" for f in result.findings)


def test_unlocked_node_and_rust_manifests_are_flagged(tmp_path: Path) -> None:
    root = _write_project(tmp_path, "name: CI\n")
    (root / "package.json").write_text("{}")
    (root / "Cargo.toml").write_text("[package]\nname='fixture'\n")
    result = run_all_checks(root)
    risks = {f.risk for f in result.findings}
    assert "unlocked-node-dependencies" in risks
    assert "unlocked-rust-dependencies" in risks
    # _write_project already writes a pyproject.toml, plus package.json + Cargo.toml
    assert result.inventory["dependency_manifests"] == 3
    assert result.inventory["lockfiles"] == 0


def test_missing_provenance_and_report_only_scan_are_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    (workflows / "release.yml").write_text(
        """name: Release
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567
"""
    )
    (workflows / "trivy.yml").write_text(
        """name: Trivy
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567
        with:
          exit-code: "0"
"""
    )
    result = run_all_checks(tmp_path)
    risks = {f.risk for f in result.findings}
    assert "missing-provenance" in risks
    assert "report-only-container-scan" in risks
    assert result.inventory["artifact_uploads"] == 1
    assert result.inventory["trivy_present"] == 1


def test_run_all_checks_rejects_non_directory_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(ValueError, match="not a directory"):
        run_all_checks(missing)


def test_format_text_output_reports_pass_and_fail() -> None:
    clean = AuditResult("/fixture", [], {})
    assert "PASS" in _format_text_output(clean)

    dirty = AuditResult(
        "/fixture",
        [Finding(Severity.HIGH, "unpinned-action", "ci.yml", "mutable ref", 3)],
        {"workflow_files": 1},
    )
    text = _format_text_output(dirty)
    assert "FAIL" in text
    assert "unpinned-action" in text


def test_main_json_output_and_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _write_project(
        tmp_path,
        """name: CI
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
""",
    )
    sys.argv = ["oss_risk_audit", str(root), "--json"]
    exit_code = main()
    out = capsys.readouterr().out
    assert exit_code == 1
    payload = json.loads(out)
    assert payload["findings"]


def test_main_reports_bad_project_path(capsys: pytest.CaptureFixture[str]) -> None:
    sys.argv = ["oss_risk_audit", "/definitely/does/not/exist"]
    exit_code = main()
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "Audit failed" in err
