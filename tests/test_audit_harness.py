from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_audit_harness_handles_static_repo_without_python_or_docker(
    tmp_path: Path,
) -> None:
    project = tmp_path / "static-site"
    project.mkdir()
    (project / "index.md").write_text("# Static site\n", encoding="utf-8")
    (project / "CNAME").write_text("example.org\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "osv-scanner",
        "#!/usr/bin/env sh\necho 'fake osv-scanner pass'\n",
    )
    _write_executable(
        fake_bin / "gitleaks",
        "#!/usr/bin/env sh\necho 'fake gitleaks pass'\n",
    )
    _write_executable(
        fake_bin / "docker",
        "#!/usr/bin/env sh\nexit 127\n",
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "audit.sh"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    result = subprocess.run(
        ["bash", str(script), str(project)],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert result.returncode == 0, result.stdout
    assert "ruff (skipped)" in result.stdout
    assert "bandit (skipped)" in result.stdout
    assert "mypy (skipped)" in result.stdout
    assert "pip-audit (skipped)" in result.stdout
    assert "gitleaks-tree" in result.stdout
    assert "shellcheck (skipped)" in result.stdout
    assert "semgrep (skipped)" in result.stdout
    assert "risky-exec (skipped)" in result.stdout
    assert "All applicable tools passed." in result.stdout


def test_audit_harness_uses_requirements_files_for_pip_audit(tmp_path: Path) -> None:
    project = tmp_path / "docs"
    project.mkdir()
    (project / "requirements.txt").write_text("mkdocs>=1.6\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "ruff",
        "#!/usr/bin/env sh\nexit 0\n",
    )
    _write_executable(
        fake_bin / "pip-audit",
        '#!/usr/bin/env sh\nprintf "%s\\n" "$@" > "$PIP_AUDIT_ARGS_FILE"\n',
    )
    _write_executable(
        fake_bin / "osv-scanner",
        "#!/usr/bin/env sh\necho 'fake osv-scanner pass'\n",
    )
    _write_executable(
        fake_bin / "gitleaks",
        "#!/usr/bin/env sh\necho 'fake gitleaks pass'\n",
    )
    _write_executable(
        fake_bin / "docker",
        "#!/usr/bin/env sh\nexit 127\n",
    )

    args_file = tmp_path / "pip-audit-args.txt"
    script = Path(__file__).resolve().parents[1] / "scripts" / "audit.sh"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    env["PIP_AUDIT_ARGS_FILE"] = str(args_file)
    result = subprocess.run(
        ["bash", str(script), str(project)],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert result.returncode == 0, result.stdout
    assert args_file.read_text(encoding="utf-8").splitlines() == [
        "-r",
        str(project / "requirements.txt"),
    ]


def test_audit_harness_remains_macos_bash_compatible() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "audit.sh"
    text = script.read_text(encoding="utf-8")

    assert "declare -A" not in text
