# LegionForge dev-rig

Shared CI pipeline, pre-commit hooks, and pytest fixtures for LegionForge projects.

---

## What's in here

| Path | Purpose |
|---|---|
| `.github/workflows/lint.yml` | Reusable CI job: ruff + bandit + mypy |
| `.github/workflows/test.yml` | Reusable CI job: pytest + coverage enforcement |
| `.github/workflows/sast.yml` | Reusable CI job: semgrep (p/python + p/fastapi) + CodeQL |
| `.github/workflows/audit.yml` | Reusable CI job: pip-audit CVE scan + pip-licenses compliance |
| `.github/workflows/supply-chain.yml` | Reusable CI job: osv-scanner (multi-ecosystem deps + malicious packages) + risky-exec custom rules + optional Socket.dev |
| `.github/workflows/secrets.yml` | Reusable CI job: gitleaks secret scanning |
| `.github/workflows/sbom.yml` | Reusable CI job: CycloneDX SBOM generation |
| `semgrep/legionforge-risky-exec.yml` | Custom Semgrep ruleset: curl\|bash installers, PowerShell download-cradles, decode-and-exec, TLS bypass |
| `scripts/audit.sh` / `scripts/audit.ps1` | Local audit harness — Python + osv-scanner + shellcheck + semgrep + risky-exec |
| `.pre-commit-hooks.yaml` | Hook definitions consumed via pre-commit |
| `.pre-commit-config.yaml` | Default config to copy into new projects (includes gitleaks, shellcheck, osv-scanner) |
| `SECURITY.md` | Vulnerability disclosure policy template — copy and adjust |
| `src/legionforge_dev_rig/fixtures/` | Shared pytest fixtures (httpx mocking, etc.) |
| `examples/` | Template conftest.py and example tests |

---

## Consuming a new project

### 1 — Install dev-rig as a dev dependency

Until published to PyPI, install path-editable from a local clone:

```bash
# From the consuming project's root
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
pre-commit run --all-files   # validate clean baseline
```

### 3 — Wire up CI

Copy the caller block from `ci.yml` comments in llm-valet, or use this template:

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
      source-dirs: "my_package"          # ← your source directories

  test:
    uses: LegionForge/dev-rig/.github/workflows/test.yml@main
    with:
      coverage-source: "my_package"      # ← package name for --cov
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
```

> **Multi-language note.** `supply-chain.yml` and the local `audit.sh`/`audit.ps1`
> harness cover Python, JS/TS, and Rust (via osv-scanner lockfile scanning) plus
> shell (shellcheck) and risky-exec patterns in shell/PowerShell/CI YAML. Each
> section self-skips when its files or tools aren't present, so the rig is safe
> to wire into any repo regardless of language mix. cargo-deny (Rust policy) and
> PSScriptAnalyzer (PowerShell SAST) are the planned next additions.

### 4 — Add shared fixtures to tests/conftest.py

```python
# tests/conftest.py
from legionforge_dev_rig.fixtures import mock_http_client, respx_mock_base_url

__all__ = ["mock_http_client", "respx_mock_base_url"]
```

Fixtures are then available in all tests without imports. See `examples/test_provider_http_example.py` for usage.

---

## Updating the rig

When you add or change a reusable workflow or fixture:

1. Bump the version in `pyproject.toml`
2. Tag the release: `git tag v0.x.0 && git push --tags`
3. In consuming projects, update `.pre-commit-config.yaml` `rev:` and the `@main` pin in CI calls

To pull the latest hooks in all projects at once:

```bash
pre-commit autoupdate
```

---

## Tool versions

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
