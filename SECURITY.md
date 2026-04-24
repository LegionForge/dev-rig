# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No — upgrade to latest |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues to: jp@legionforge.org

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Suggested fix if you have one

You will receive an acknowledgement within 72 hours. We aim to release a fix within 14 days for critical issues.

## Disclosure Policy

We follow coordinated disclosure:
1. You report privately
2. We confirm and assess within 72 hours
3. We fix and prepare a release
4. We notify you when the fix is available
5. We publish a security advisory on GitHub

We request that you do not disclose publicly until a fix is released, or 90 days have elapsed (whichever comes first).

## Security Controls

This project applies the following controls aligned with OWASP SAMM Level 1:

| Control | Tool | Where |
|---------|------|--------|
| Static analysis | bandit, semgrep (p/python, p/fastapi), CodeQL | CI (`sast.yml`) |
| Dependency CVE scan | pip-audit | CI (`audit.yml`) |
| License compliance | pip-licenses | CI (`audit.yml`) |
| Secret scanning | gitleaks | CI (`secrets.yml`) + pre-commit |
| SBOM generation | CycloneDX | CI (`sbom.yml`) — artifacts on each release |
| Pre-commit hooks | ruff, bandit, mypy, gitleaks | Local dev |

## Threat Model

See `CLAUDE.md` or project documentation for the full threat model (T1–T8).
