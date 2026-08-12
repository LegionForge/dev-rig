# External Review Package

## Scope

This repository provides reusable CI/CD controls. It is not a replacement for
application-specific threat modeling or runtime penetration testing. Consumers
must select the workflows appropriate to their language and deployment model.

## Controls implemented

- SHA-pinned GitHub Actions with disabled checkout credential persistence.
- Explicit least-privilege permissions, job timeouts, and concurrency cancellation.
- Environment-mediated and validated reusable-workflow inputs.
- Python, Node, and Rust dependency auditing and license checks.
- Semgrep, Bandit, CodeQL, gitleaks, Trivy, and OWASP ZAP integration.
- Fail-closed scanner policy for high/critical findings.
- ZAP JSON validation before SARIF conversion and upload.
- Filesystem and optional built-image Trivy scanning.
- CycloneDX SBOM generation and reusable artifact provenance attestation.
- Deterministic static control audit with negative contract tests.
- Scheduled drift auditing through `oss-audit.yml`.

## Evidence commands

```bash
python -m pytest -q
python -m ruff check src tests
python -m black --check --target-version py311 src tests
python -m mypy src
python -m legionforge_dev_rig.oss_risk_audit . --strict
zizmor .github/workflows --pedantic --min-severity high
shellcheck scripts/audit.sh
```

The expected baseline is zero HIGH/MEDIUM findings from the static audit and
zero HIGH findings from zizmor. Informational, low, and medium zizmor findings must be reviewed
and either fixed or documented with a narrow, line-level suppression.

## Consumer prerequisites

Before production use, each consuming repository should enable required status
checks and branch protection, pin its `dev-rig` reusable workflow reference to
a release tag or commit SHA, enable Dependabot/code scanning/secret scanning,
and verify release attestations with:

```bash
gh attestation verify path/to/artifact \
  --repo ORGANIZATION/REPOSITORY \
  --signer-repo LegionForge/dev-rig
```

## Known boundaries

- Static controls cannot prove application authorization or business-logic safety.
- ZAP baseline is passive by default; authenticated and active scans require a
  consumer-specific context and authorization.
- Trivy filesystem scanning does not replace scanning the final pushed image.
- Exceptions require an owner, reason, tracking issue, and expiry date.
