"""OSS risk audit tool — discovers and reports on OSS supply chain risks."""

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Risk severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """A single risk finding."""

    severity: Severity
    risk: str
    file: str
    message: str


@dataclass
class AuditResult:
    """Result of a complete audit run."""

    project: str
    findings: list[Finding]
    inventory: dict


def _format_text_output(result: AuditResult, strict: bool = False) -> str:
    """Format audit result as human-readable text."""
    lines = []

    # Inventory block
    lines.append("=== Inventory ===")
    if result.inventory:
        for key, value in result.inventory.items():
            lines.append(f"{key}: {value}")
    else:
        lines.append("(no inventory)")
    lines.append("")

    # Findings table
    lines.append("=== Findings ===")
    if result.findings:
        for finding in result.findings:
            lines.append(
                f"[{finding.severity}] {finding.risk}: {finding.file} — {finding.message}"
            )
    else:
        lines.append("None")
    lines.append("")

    # Summary
    num_high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    num_medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    num_low = sum(1 for f in result.findings if f.severity == Severity.LOW)
    lines.append(f"Summary: {num_high} HIGH, {num_medium} MEDIUM, {num_low} LOW")

    # Determine pass/fail
    has_high = num_high > 0
    has_medium = num_medium > 0
    should_fail = has_high or (strict and has_medium)
    status = "FAIL" if should_fail else "PASS"
    lines.append(status)

    return "\n".join(lines)


def _format_json_output(result: AuditResult) -> str:
    """Format audit result as JSON."""
    data = {
        "project": result.project,
        "findings": [asdict(f) for f in result.findings],
        "inventory": result.inventory,
    }
    return json.dumps(data, indent=2, default=str)


def run_all_checks(project_path: Path, config: dict | None = None) -> AuditResult:
    """
    Run all audit checks on a project.

    Args:
        project_path: Root of the project to audit.
        config: Optional configuration dict.

    Returns:
        AuditResult with findings and inventory.
    """
    return AuditResult(
        project=str(project_path),
        findings=[],
        inventory={},
    )


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Audit a project for OSS supply chain risks."
    )
    parser.add_argument(
        "project_path",
        type=Path,
        help="Path to the project to audit",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat MEDIUM findings as failures (default: only HIGH is failure)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to audit configuration file",
    )

    args = parser.parse_args()

    # Load config if provided
    config = {}
    if args.config:
        try:
            with open(args.config) as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
            return 1

    # Run audit
    try:
        result = run_all_checks(args.project_path, config)
    except Exception as e:
        print(f"Audit failed: {e}", file=sys.stderr)
        return 1

    # Output
    if args.json:
        output = _format_json_output(result)
    else:
        output = _format_text_output(result, strict=args.strict)

    print(output)

    # Determine exit code
    has_findings = len(result.findings) > 0
    if has_findings:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
