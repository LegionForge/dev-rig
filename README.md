# LegionForge dev-rig

Shared CI pipeline, pre-commit hooks, and test fixtures for LegionForge projects.
Supports Python, Node/TypeScript, and Rust. C is planned.

The rig itself is continuously audited. Its control audit checks workflow
permissions, timeouts, concurrency, SHA-pinned actions, checkout credential
persistence, reusable-workflow input injection, dependency lockfiles, and
scanner failure policy. The audit is intentionally complementary to
pip-audit, npm audit, cargo-audit, Semgrep, CodeQL, Trivy, ZAP, and gitleaks.

---

## Workflow inventory

### Python

| Path | Purpose |
|---|---|
| `.github/workflows/lint.yml` | ruff + bandit + mypy |
| `.github/workflows/test.yml` | pytest + coverage enforcement |
| `.github/workflows/sast.yml` | semgrep (p/python + p/fastapi) + CodeQL |
| `.github/workflows/audit.yml` | pip-audit CVE scan + pip-licenses compliance |
| `.github/workflows/sbom.yml` | CycloneDX SBOM generation |

### Node / TypeScript

| Path | Purpose |
|---|---|
| `.github/workflows/node-lint.yml` | tsc --noEmit + eslint (skipped if unconfigured) |
| `.github/workflows/node-test.yml` | vitest/jest + coverage upload |
| `.github/workflows/node-sast.yml` | semgrep (p/javascript p/typescript p/nodejs) + CodeQL |
| `.github/workflows/node-audit.yml` | npm audit CVE scan + license-checker compliance |
| `.github/workflows/node-sbom.yml` | CycloneDX SBOM generation |

### Language-agnostic

| Path | Purpose |
|---|---|
| `.github/workflows/secrets.yml` | gitleaks secret scanning — works for any language |
| `.github/workflows/dast.yml` | ZAP baseline scan with JSON validation and SARIF conversion |
| `.github/workflows/trivy.yml` | filesystem and optional built-image scan |
| `.github/workflows/oss-audit.yml` | dev-rig control-plane audit and scheduled drift check |
| `.github/workflows/attest.yml` | reusable artifact provenance attestation |

### Other

| Path | Purpose |
|---|---|
| `.github/workflows/supply-chain.yml` | Reusable CI job: osv-scanner (multi-ecosystem deps + malicious packages) + risky-exec custom rules + optional Socket.dev |
| `semgrep/legionforge-risky-exec.yml` | Custom Semgrep ruleset: curl\|bash installers, PowerShell download-cradles, decode-and-exec, TLS bypass |
| `scripts/audit.sh` / `scripts/audit.ps1` | Local audit harness — Python when applicable + gitleaks + osv-scanner + shellcheck + semgrep + risky-exec |
| `.pre-commit-hooks.yaml` | Hook definitions consumed via pre-commit |
| `.pre-commit-config.yaml` | Default config to copy into new projects (includes gitleaks, shellcheck, osv-scanner) |
| `SECURITY.md` | Vulnerability disclosure policy template — copy and adjust |
| `EXTERNAL-REVIEW.md` | Control inventory, evidence commands, and review boundaries |
| `src/legionforge_dev_rig/fixtures/` | Shared pytest fixtures (httpx mocking, etc.) |
| `examples/` | Template conftest.py and example tests |

---

## Python projects

### 1 — Install dev-rig as a dev dependency

Until published to PyPI, install path-editable from a local clone:

```bash
pip install -e "../../LegionForge-dev-rig/dev-rig"

# Or once published:
pip install legionforge-dev-rig
```

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
dev = [
    # ... project deps ...
    "legionforge-dev-rig",
]
```

### 2 — Copy the pre-commit config

```bash
cp ../../LegionForge-dev-rig/dev-rig/.pre-commit-config.yaml .
```

Adjust the `additional_dependencies` under the mypy hook to match your project's runtime deps, then:

```bash
pre-commit install
pre-commit run --all-files
```

### 3 — Wire up CI

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]

jobs:
  lint:
    uses: LegionForge/dev-rig/.github/workflows/lint.yml@main
    with:
      source-dirs: "my_package"

  test:
    uses: LegionForge/dev-rig/.github/workflows/test.yml@main
    with:
      coverage-source: "my_package"
      coverage-threshold: 80

  sast:
    uses: LegionForge/dev-rig/.github/workflows/sast.yml@main
    with:
      source-dirs: "my_package/"
    permissions:
      security-events: write

  audit:
    uses: LegionForge/dev-rig/.github/workflows/audit.yml@main

  supply-chain:
    uses: LegionForge/dev-rig/.github/workflows/supply-chain.yml@main
    secrets: inherit                   # ← only needed to enable the optional Socket.dev scan

  secrets:
    uses: LegionForge/dev-rig/.github/workflows/secrets.yml@main
```

> **Multi-language note.** `supply-chain.yml` and the local `audit.sh`/`audit.ps1`
> harness cover Python, JS/TS, and Rust (via osv-scanner lockfile scanning) plus
> shell (shellcheck) and risky-exec patterns in shell/PowerShell/CI YAML. Each
> section self-skips when its files or tools aren't present, so the rig is safe
> to wire into any repo regardless of language mix. cargo-deny (Rust policy) and
> PSScriptAnalyzer (PowerShell SAST) are the planned next additions.

> **Static-site note.** Repos with no package or Python sources are still
> auditable. The local harness skips Python-only tools, then still runs the
> applicable checks: gitleaks, osv-scanner, shellcheck when shell files exist,
> Semgrep packs when Docker is available, and the LegionForge risky-exec rules.
> A result of "nothing applicable" is a valid audit outcome, not a reason to
> skip the repo.

### 4 — Add shared fixtures to tests/conftest.py

```python
# tests/conftest.py
from legionforge_dev_rig.fixtures import mock_http_client, respx_mock_base_url

__all__ = ["mock_http_client", "respx_mock_base_url"]
```

---

## Node / TypeScript projects

### Expected npm scripts

dev-rig calls these script names directly. Add them to `package.json`:

```json
"scripts": {
  "typecheck":      "tsc --noEmit",
  "lint":           "eslint src/",
  "test":           "vitest run",
  "test:coverage":  "vitest run --coverage",
  "build":          "tsup"
}
```

ESLint is optional — `node-lint.yml` skips it if no ESLint config file is present.
When you add ESLint, install `eslint` + `@typescript-eslint/eslint-plugin` +
`@typescript-eslint/parser` in devDependencies and add `eslint.config.js`.

Coverage threshold is enforced by the test runner config (`vitest.config.ts`
`coverage.thresholds` or `jest.config` `coverageThreshold`), not by this workflow.

### Wire up CI

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]

jobs:
  lint:
    uses: LegionForge/dev-rig/.github/workflows/node-lint.yml@main
    with:
      source-dirs: "src"

  test:
    uses: LegionForge/dev-rig/.github/workflows/node-test.yml@main
    with:
      coverage-threshold: 80

  sast:
    uses: LegionForge/dev-rig/.github/workflows/node-sast.yml@main
    with:
      source-dirs: "src"
    permissions:
      security-events: write

  audit:
    uses: LegionForge/dev-rig/.github/workflows/node-audit.yml@main

  secrets:
    uses: LegionForge/dev-rig/.github/workflows/secrets.yml@main
```

---

## Updating the rig

When you add or change a reusable workflow or fixture:

1. Bump the version in `pyproject.toml`
2. Tag the release: `git tag v0.x.0 && git push --tags`
3. In consuming projects, update `.pre-commit-config.yaml` `rev:` and `@main` pins

To pull the latest hooks in all projects at once:

```bash
pre-commit autoupdate
```

### External review checklist

Before requesting review, run:

```bash
python -m pytest -q
python -m legionforge_dev_rig.oss_risk_audit . --strict
zizmor .github/workflows --pedantic
shellcheck scripts/audit.sh
```

Reviewers should also confirm that the consuming repository pins the dev-rig
workflow to a release tag or commit SHA, enables required status checks, and
has GitHub Dependabot alerts, secret scanning, code scanning, and dependency
review enabled. Release artifacts should be verified with `gh attestation
verify` after publishing.

---

## Tool versions

### Python

| Tool | Minimum version | Config location |
|---|---|---|
| ruff | 0.4 | `pyproject.toml [tool.ruff]` |
| bandit | 1.7 | `pyproject.toml [tool.bandit]` |
| mypy | 1.10 | `pyproject.toml [tool.mypy]` |
| pip-audit | 2.7 | no config — runs against installed packages |
| osv-scanner | 2.3 | no config — scans lockfiles recursively (`brew install osv-scanner`) |
| shellcheck | 0.10 | inline directives / `.shellcheckrc` (`brew install shellcheck`) |
| semgrep | 1.70 | rulesets passed as CLI args + `semgrep/legionforge-risky-exec.yml` |
| pytest-cov | 5 | `pyproject.toml [tool.pytest.ini_options]` |
| pre-commit | 3.7 | `.pre-commit-config.yaml` |

### Node / TypeScript

| Tool | Minimum version | Config location |
|---|---|---|
| typescript | 5 | `tsconfig.json` |
| eslint | 9 | `eslint.config.js` (flat config) |
| @typescript-eslint | 8 | `eslint.config.js` |
| vitest | 2 | `vitest.config.ts` |
| @vitest/coverage-v8 | 2 | `vitest.config.ts coverage.*` |
| license-checker | 25 | no config — allowlist passed as CLI arg |
| @cyclonedx/cyclonedx-npm | 1 | no config |

---

## OWASP Coverage

dev-rig provides multi-layered security testing aligned with OWASP SAMM maturity practices and OWASP Top 10 vulnerability categories:

### SAST (Static Application Security Testing)

| Tool | Workflow | OWASP Coverage |
|------|----------|---|
| Semgrep (p/python) | `lint.yml` | A01 (Broken Access Control—partial), A02 (Cryptographic Failures), A03 (Injection—SQL/CMD/SSTI), A05 (Security Misconfiguration), A08 (Software/Data Integrity) |
| Semgrep (p/fastapi) | `lint.yml` | A01 (CORS/Auth misconfiguration), A07 (Identification/Authentication Failures), A02 (JWT issues) |
| CodeQL (security-extended) | `sast.yml` | A03 (Injection—taint-flow), A10 (SSRF), A01 (Access Control—partial) |
| Bandit | `lint.yml` | A02 (Cryptographic Failures), A06 (Vulnerable Components), A08 (Integrity) |

### Dependency Audit

| Tool | Workflow | OWASP Coverage |
|------|----------|---|
| pip-audit | `audit.yml` | A06 (Vulnerable and Outdated Components) |
| pip-licenses | `audit.yml` | A06 (License compliance—supply chain risk) |

### Secret Scanning

| Tool | Workflow | OWASP Coverage |
|------|----------|---|
| gitleaks | `secrets.yml` | A02 (Cryptographic Failures—leaked credentials/keys) |

### Dynamic Application Security Testing (DAST)

| Tool | Workflow | OWASP Coverage |
|------|----------|---|
| OWASP ZAP | `dast.yml` | A01 (Auth enforcement at runtime), A05 (Missing security headers), A06 (Session/token lifecycle), A09 (Logging/Monitoring—response leakage) |

### Coverage Gaps: What SAST Alone Cannot Verify

SAST tools (semgrep, CodeQL, bandit) analyze source code and can detect injection patterns, weak crypto, hardcoded secrets, and dependency vulnerabilities. However, they **cannot test behavior at runtime**:

- **Authentication enforcement** — whether `/login` actually rejects bad credentials, whether protected endpoints block unauthenticated requests
- **HTTP security headers** — `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, etc. (not added by most frameworks by default)
- **Session/token lifecycle** — expiration, token refresh, session fixation
- **Information disclosure in error responses** — whether 500 errors leak stack traces or internal paths
- **Rate limiting and DoS prevention** — not visible in code analysis

**DAST bridges this gap** by running the application and probing it against real HTTP requests.

### Recommended CI Configuration for Web Services

For FastAPI, Django, Flask, Node.js/Express, and other web services, integrate both SAST and DAST:

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]

jobs:
  lint:
    uses: LegionForge/dev-rig/.github/workflows/lint.yml@main
    with:
      source-dirs: "src"

  test:
    uses: LegionForge/dev-rig/.github/workflows/test.yml@main
    with:
      coverage-source: "src"
      coverage-threshold: 80

  sast:
    uses: LegionForge/dev-rig/.github/workflows/sast.yml@main
    with:
      source-dirs: "src"
    permissions:
      security-events: write

  audit:
    uses: LegionForge/dev-rig/.github/workflows/audit.yml@main

  secrets:
    uses: LegionForge/dev-rig/.github/workflows/secrets.yml@main

  dast:
    needs: [test]  # Only run DAST after unit tests pass
    uses: LegionForge/dev-rig/.github/workflows/dast.yml@main
    with:
      target-url: "http://localhost:9766"
      fail-on-severity: "High"
    permissions:
      security-events: write
```

**Important:** The `dast.yml` workflow **does not start your service**. The caller workflow (in your repo) is responsible for:

1. Spinning up the service in Docker Compose or Kubernetes
2. Polling `/health` or equivalent until the service is ready
3. Invoking `dast.yml` with the target URL
4. Cleaning up containers/processes after scan completes

See `LegionForge/LegionForge-Guardian/.github/workflows/dast.yml` for a complete example.

---

## OWASP Top 10 Quick Reference

| Category | What it is | dev-rig Coverage |
|---|---|---|
| A01: Broken Access Control | Auth/authz failures, CORS issues, privilege escalation | SAST (semgrep/CodeQL) + DAST (ZAP) |
| A02: Cryptographic Failures | Weak crypto, hardcoded secrets, TLS issues | SAST (semgrep/bandit) + Audit (gitleaks) |
| A03: Injection | SQL, command, LDAP, template injection | SAST (semgrep/CodeQL—taint-flow) |
| A04: Insecure Design | Missing controls by design (no auth model, etc.) | **Not covered — requires threat modeling** |
| A05: Security Misconfiguration | Missing headers, exposed services, bad defaults | SAST (semgrep p/fastapi) + DAST (ZAP headers) |
| A06: Vulnerable Components | Known CVEs in dependencies | Audit (pip-audit) |
| A07: Authentication Failures | Weak password policy, session fixation | SAST (semgrep p/fastapi) + DAST (ZAP) |
| A08: Data Integrity Failures | Serialization bugs, unsigned updates | SAST (semgrep/CodeQL) |
| A09: Logging/Monitoring Failures | Missing logs, response leakage | DAST (ZAP scans for info disclosure) |
| A10: SSRF | Server-side request forgery | SAST (CodeQL—taint tracking) |
