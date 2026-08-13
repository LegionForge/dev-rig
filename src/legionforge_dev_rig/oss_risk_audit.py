"""Deterministic static audit for CI/CD supply-chain controls.

This is intentionally dependency-light. It does not replace pip-audit,
Semgrep, CodeQL, Trivy, or gitleaks; it verifies that those controls are
configured safely and that their failure paths cannot silently pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    risk: str
    file: str
    message: str
    line: int | None = None


@dataclass
class AuditResult:
    project: str
    findings: list[Finding]
    inventory: dict[str, Any]


ACTION_RE = re.compile(r"(?m)^[ \t-]*uses:\s*[^\s#]+@([^\s#]+)")
INPUT_RE = re.compile(r"\$\{\{\s*inputs\.([\w-]+)\s*\}\}")
WORKFLOW_RE = re.compile(r"\.github/workflows/[^\s]+\.ya?ml$")


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root))


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _add(
    findings: list[Finding],
    severity: Severity,
    risk: str,
    path: Path,
    root: Path,
    message: str,
    line: int | None = None,
) -> None:
    findings.append(Finding(severity, risk, _rel(path, root), message, line))


def _workflow_checks(root: Path, findings: list[Finding]) -> dict[str, int]:
    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    action_count = 0
    mutable_actions = 0
    input_shell_uses = 0
    for path in workflows:
        text = path.read_text(encoding="utf-8", errors="replace")
        if "permissions:" not in text:
            _add(
                findings,
                Severity.MEDIUM,
                "workflow-permissions",
                path,
                root,
                "Workflow has no explicit least-privilege permissions block.",
            )
        # Jobs that call a reusable workflow (`uses: ./x.yml` with no
        # `runs-on:`) can't set timeout-minutes themselves -- GitHub Actions
        # rejects that key there. Timeout enforcement lives in the called
        # workflow's own jobs, so a pure-orchestrator file (no runs-on:
        # anywhere) has nothing on this runner that could hang.
        if "runs-on:" in text and "timeout-minutes:" not in text:
            _add(
                findings,
                Severity.MEDIUM,
                "workflow-timeout",
                path,
                root,
                "Workflow has no job timeout; a hung scanner can consume a runner indefinitely.",
            )
        if "concurrency:" not in text:
            _add(
                findings,
                Severity.LOW,
                "workflow-concurrency",
                path,
                root,
                "Workflow has no concurrency cancellation policy.",
            )
        if "continue-on-error: true" in text:
            _add(
                findings,
                Severity.HIGH,
                "silent-failure",
                path,
                root,
                "Workflow permits a step to fail without a separate policy decision.",
            )
        for match in ACTION_RE.finditer(text):
            action_count += 1
            ref = match.group(1)
            line = _line_number(text, match.start())
            if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                mutable_actions += 1
                _add(
                    findings,
                    Severity.HIGH,
                    "unpinned-action",
                    path,
                    root,
                    f"Action reference @{ref} is mutable; pin it to a 40-character commit SHA.",
                    line,
                )
        for match in re.finditer(r"uses:\s*actions/checkout@[^\n]+", text):
            line = _line_number(text, match.start())
            block = text[
                match.start() : (
                    text.find("\n\n", match.start())
                    if text.find("\n\n", match.start()) >= 0
                    else len(text)
                )
            ]
            if "persist-credentials: false" not in block:
                _add(
                    findings,
                    Severity.MEDIUM,
                    "credential-persistence",
                    path,
                    root,
                    "Checkout does not disable persisted Git credentials.",
                    line,
                )
        for match in INPUT_RE.finditer(text):
            line = _line_number(text, match.start())
            before = text[max(0, match.start() - 300) : match.start()]
            if "run:" in before and "env:" not in before:
                input_shell_uses += 1
                _add(
                    findings,
                    Severity.HIGH,
                    "template-injection",
                    path,
                    root,
                    (
                        f"workflow input '{match.group(1)}' is interpolated into shell "
                        "without env indirection."
                    ),
                    line,
                )
    return {
        "workflow_files": len(workflows),
        "action_references": action_count,
        "mutable_action_references": mutable_actions,
        "unsafe_shell_input_references": input_shell_uses,
    }


def _manifest_checks(root: Path, findings: list[Finding]) -> dict[str, int]:
    manifests = [
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.name
        in {
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "Cargo.toml",
            "Cargo.lock",
        }
        and ".git" not in p.parts
        and "node_modules" not in p.parts
    ]
    names = {p.name for p in manifests}
    if "package.json" in names and "package-lock.json" not in names:
        _add(
            findings,
            Severity.MEDIUM,
            "unlocked-node-dependencies",
            root / "package.json",
            root,
            (
                "Node project has package.json but no package-lock.json; npm ci "
                "cannot guarantee dependency integrity."
            ),
        )
    if "Cargo.toml" in names and "Cargo.lock" not in names:
        _add(
            findings,
            Severity.MEDIUM,
            "unlocked-rust-dependencies",
            root / "Cargo.toml",
            root,
            (
                "Rust project has Cargo.toml but no Cargo.lock; release dependency "
                "resolution is not reproducible."
            ),
        )
    return {
        "dependency_manifests": len(manifests),
        "lockfiles": sum(p.name.endswith("lock") for p in manifests),
    }


def _artifact_checks(root: Path, findings: list[Finding]) -> dict[str, int]:
    workflow_paths = list((root / ".github" / "workflows").glob("*.y*ml"))
    workflow_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in workflow_paths
    )
    release_paths = [p for p in workflow_paths if re.search(r"(publish|release|build)", p.name)]
    release_text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in release_paths)
    if "upload-artifact" in release_text and "attest-build-provenance" not in release_text:
        _add(
            findings,
            Severity.MEDIUM,
            "missing-provenance",
            root / ".github" / "workflows",
            root,
            "Release/build workflow uploads artifacts but does not attest provenance.",
        )
    if "trivy-action" in workflow_text and 'exit-code: "0"' in workflow_text:
        _add(
            findings,
            Severity.MEDIUM,
            "report-only-container-scan",
            root / ".github" / "workflows",
            root,
            "Trivy is configured report-only; high/critical findings do not fail CI.",
        )
    return {
        "artifact_uploads": workflow_text.count("upload-artifact"),
        "provenance_attestation_configured": int("attest-build-provenance" in workflow_text),
        "trivy_present": int("trivy-action" in workflow_text),
    }


def run_all_checks(project_path: Path, config: dict[str, Any] | None = None) -> AuditResult:
    """Run deterministic repository control checks."""
    root = project_path.resolve()
    findings: list[Finding] = []
    inventory: dict[str, Any] = {}
    if not root.is_dir():
        raise ValueError(f"project path is not a directory: {root}")
    inventory.update(_workflow_checks(root, findings))
    inventory.update(_manifest_checks(root, findings))
    inventory.update(_artifact_checks(root, findings))
    config = config or {}
    ignored = set(config.get("ignore-risks", []))
    findings = [f for f in findings if f.risk not in ignored]
    inventory["ignored_risks"] = sorted(ignored)
    return AuditResult(str(root), findings, inventory)


def _format_text_output(result: AuditResult, strict: bool = False) -> str:
    lines = ["=== Inventory ==="]
    lines.extend(f"{key}: {value}" for key, value in result.inventory.items())
    lines.append("\n=== Findings ===")
    lines.extend(
        f"[{f.severity.value}] {f.risk}: {f.file}" f"{f':{f.line}' if f.line else ''} — {f.message}"
        for f in result.findings
    )
    if not result.findings:
        lines.append("None")
    counts = {
        severity: sum(f.severity == severity for f in result.findings) for severity in Severity
    }
    lines.append(
        f"\nSummary: {counts[Severity.HIGH]} HIGH, "
        f"{counts[Severity.MEDIUM]} MEDIUM, {counts[Severity.LOW]} LOW"
    )
    lines.append(
        "FAIL" if counts[Severity.HIGH] or (strict and counts[Severity.MEDIUM]) else "PASS"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a project for OSS supply-chain risks.")
    parser.add_argument("project_path", type=Path)
    parser.add_argument("--strict", action="store_true", help="Treat MEDIUM findings as failures")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--config", type=Path, help="JSON config containing ignore-risks")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text()) if args.config else {}
        result = run_all_checks(args.project_path, config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(
            json.dumps(
                {
                    "project": result.project,
                    "findings": [asdict(f) for f in result.findings],
                    "inventory": result.inventory,
                },
                indent=2,
                default=str,
            )
        )
    else:
        print(_format_text_output(result, strict=args.strict))
    return int(
        any(
            f.severity == Severity.HIGH or (args.strict and f.severity == Severity.MEDIUM)
            for f in result.findings
        )
    )


if __name__ == "__main__":
    sys.exit(main())
