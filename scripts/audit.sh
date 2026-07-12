#!/usr/bin/env bash
# LegionForge audit harness.
#   Python  : ruff, bandit, mypy, pip-audit (only when Python files/deps exist)
#   All deps: osv-scanner (Python / npm / Cargo / … vulns + malicious packages)
#   Secrets : gitleaks (working tree + git history)
#   Shell   : shellcheck
#   Patterns: semgrep (per-project packs) + risky-exec (custom supply-chain rules)
#
# Language sections self-skip when their files/tools aren't present, so the same
# harness runs cleanly against single- and multi-language repos.
#
# Usage:
#   ./audit.sh                        # from the project root
#   ./audit.sh /path/to/project       # from anywhere
#
# Per-project config (place at project root):
#   .audit-dirs       — space-separated source dirs  (e.g. "llm_valet svcmgr")
#   .semgrep-configs  — space-separated semgrep rule packs (e.g. "p/python p/fastapi")
#
# This script is intentionally compatible with macOS's Bash 3.2. Do not use
# associative arrays.

set -euo pipefail

# Resolve the dev-rig root (this script lives in <rig>/scripts/) so the bundled
# custom Semgrep ruleset is found regardless of the consuming project's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RIG_ROOT="$(dirname "$SCRIPT_DIR")"

PROJECT="${1:-$(pwd)}"
PROJECT="$(cd "$PROJECT" && pwd)"   # resolve to absolute path

# ── Read per-project config ───────────────────────────────────────────────────

if [[ -f "$PROJECT/.audit-dirs" ]]; then
    SOURCE_DIRS="$(cat "$PROJECT/.audit-dirs" | tr -d '\r')"
else
    SOURCE_DIRS="."
fi

if [[ -f "$PROJECT/.semgrep-configs" ]]; then
    SEMGREP_CONFIGS="$(cat "$PROJECT/.semgrep-configs" | tr -d '\r')"
else
    SEMGREP_CONFIGS="p/python"
fi

# ── Output helpers ────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RESET='\033[0m'

declare -a RESULTS=()

section() { echo -e "\n${GRAY}── $1 $(printf '─%.0s' $(seq 1 $((62 - ${#1}))))${RESET}"; }

record_result() {
    local name="$1"
    local status="$2"
    RESULTS+=("$name::$status")
}

run_tool() {
    local name="$1"
    shift
    section "$name"
    pushd "$PROJECT" > /dev/null
    if "$@"; then
        echo -e "  ${GREEN}✓  $name passed${RESET}"
        record_result "$name" "PASS"
    else
        echo -e "  ${RED}✗  $name FAILED${RESET}"
        record_result "$name" "FAIL"
    fi
    popd > /dev/null
}

skip_tool() {
    local name="$1"
    local reason="$2"
    section "$name"
    echo -e "  ${GRAY}$reason${RESET}"
    record_result "$name" "SKIP"
}

find_first() {
    find "$PROJECT" "$@" -print -quit 2>/dev/null
}

has_python_code() {
    [[ -n "$(find_first -type f -name '*.py' \
        -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/venv/*' \
        -not -path '*/node_modules/*')" ]]
}

has_python_deps() {
    [[ -f "$PROJECT/pyproject.toml" || -f "$PROJECT/setup.py" || -f "$PROJECT/setup.cfg" ||
       -n "$(find_first -type f \( -name 'requirements*.txt' -o -name 'Pipfile' -o -name 'poetry.lock' -o -name 'uv.lock' \) \
           -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/venv/*' \
           -not -path '*/node_modules/*')" ]]
}

python_runner() {
    if command -v py > /dev/null 2>&1; then
        echo "py -3.13"
    elif command -v python3 > /dev/null 2>&1; then
        echo "python3"
    elif command -v python > /dev/null 2>&1; then
        echo "python"
    else
        echo ""
    fi
}

run_python_module_or_command() {
    local name="$1"
    local command_name="$2"
    local module_name="$3"
    shift 3

    if command -v "$command_name" > /dev/null 2>&1; then
        run_tool "$name" "$command_name" "$@"
    elif [[ -n "$PYTHON_RUNNER" ]]; then
        # shellcheck disable=SC2086
        run_tool "$name" $PYTHON_RUNNER -m "$module_name" "$@"
    else
        skip_tool "$name" "python interpreter not found — skipping"
    fi
}

docker_available() {
    command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1
}

# ── Header ────────────────────────────────────────────────────────────────────

echo -e "\n${CYAN}LegionForge Audit Harness${RESET}"
echo    "  Project : $PROJECT"
echo    "  Dirs    : $SOURCE_DIRS"
echo    "  Semgrep : $SEMGREP_CONFIGS"

read -ra SOURCE_DIR_LIST <<< "$SOURCE_DIRS"
PYTHON_RUNNER="$(python_runner)"
HAS_PYTHON_CODE=0
HAS_PYTHON_DEPS=0
has_python_code && HAS_PYTHON_CODE=1
has_python_deps && HAS_PYTHON_DEPS=1

# ── ruff ──────────────────────────────────────────────────────────────────────

if [[ "$HAS_PYTHON_CODE" -eq 1 || "$HAS_PYTHON_DEPS" -eq 1 ]]; then
    run_python_module_or_command "ruff" "ruff" "ruff" check "${SOURCE_DIR_LIST[@]}"
else
    skip_tool "ruff" "no Python files or dependency manifests found — skipping"
fi

# ── bandit ────────────────────────────────────────────────────────────────────

if [[ "$HAS_PYTHON_CODE" -eq 1 ]]; then
    bandit_args=("-r" "${SOURCE_DIR_LIST[@]}" "-q")
    [[ -f "$PROJECT/pyproject.toml" ]] && bandit_args+=("-c" "pyproject.toml")
    run_python_module_or_command "bandit" "bandit" "bandit" "${bandit_args[@]}"
else
    skip_tool "bandit" "no Python files found — skipping"
fi

# ── mypy ──────────────────────────────────────────────────────────────────────

if [[ "$HAS_PYTHON_CODE" -eq 1 ]]; then
    run_python_module_or_command "mypy" "mypy" "mypy" "${SOURCE_DIR_LIST[@]}"
else
    skip_tool "mypy" "no Python files found — skipping"
fi

# ── pip-audit ─────────────────────────────────────────────────────────────────

if [[ "$HAS_PYTHON_DEPS" -eq 1 ]]; then
    run_python_module_or_command "pip-audit" "pip-audit" "pip_audit" .
else
    skip_tool "pip-audit" "no Python dependency manifests found — skipping"
fi

# ── osv-scanner — multi-ecosystem dependency + malicious-package scan ──────────
# One pass over every lockfile in the repo (Python / npm / Cargo / Go / …),
# checked against the OSV database — CVEs *and* the malicious-packages feed that
# pip-audit lacks. --allow-no-lockfiles makes a repo with nothing to scan a pass,
# not a failure, so the harness stays usable everywhere.
if command -v osv-scanner > /dev/null 2>&1; then
    run_tool "osv-scanner" osv-scanner scan source --recursive --allow-no-lockfiles .
else
    skip_tool "osv-scanner" "osv-scanner not installed — skipping (brew install osv-scanner)"
fi

# ── gitleaks — secrets in working tree and history ───────────────────────────

if command -v gitleaks > /dev/null 2>&1; then
    run_tool "gitleaks-tree" gitleaks detect --source . --no-git --redact --verbose
    if [[ -d "$PROJECT/.git" ]]; then
        run_tool "gitleaks-history" gitleaks detect --source . --redact --verbose
    else
        skip_tool "gitleaks-history" "not a git checkout — skipping history scan"
    fi
else
    skip_tool "gitleaks" "gitleaks not installed — skipping (brew install gitleaks)"
fi

# ── shellcheck — shell script correctness + footguns ──────────────────────────
# Runs only when the repo actually contains shell scripts.
shell_files=()
while IFS= read -r f; do shell_files+=("$f"); done < <(
    find "$PROJECT" -type f \( -name '*.sh' -o -name '*.bash' \) \
        -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/node_modules/*' \
        -not -path '*/.claude/*' 2>/dev/null
)
if [[ ${#shell_files[@]} -gt 0 ]]; then
    if command -v shellcheck > /dev/null 2>&1; then
        run_tool "shellcheck" shellcheck "${shell_files[@]}"
    else
        skip_tool "shellcheck" "${#shell_files[@]} shell script(s) found but shellcheck not installed — skipping (brew install shellcheck)"
    fi
else
    skip_tool "shellcheck" "no shell scripts found — skipping"
fi

# ── semgrep (via Docker) ──────────────────────────────────────────────────────

semgrep_args=()
for cfg in $SEMGREP_CONFIGS; do
    semgrep_args+=("--config=$cfg")
done
for dir in "${SOURCE_DIR_LIST[@]}"; do
    semgrep_args+=("/src/$dir")
done
semgrep_args+=("--error")

# Git Bash converts /src/... paths to C:/Program Files/Git/src/... before Docker
# sees them. Two-part fix:
#   cygpath -m  — converts the host project path to Windows format for the volume mount
#   MSYS_NO_PATHCONV=1 — stops Git Bash mangling /src/... container-side paths
WIN_PROJECT=$(cygpath -m "$PROJECT" 2>/dev/null || echo "$PROJECT")
if docker_available; then
    run_tool "semgrep" env MSYS_NO_PATHCONV=1 docker run --rm \
        -v "${WIN_PROJECT}:/src" \
        semgrep/semgrep \
        semgrep "${semgrep_args[@]}" \
        --exclude .git --exclude node_modules
else
    skip_tool "semgrep" "docker unavailable — skipping containerized Semgrep"
fi

# ── risky-exec — LegionForge custom supply-chain / RCE pattern rules ───────────
# Flags curl|bash installers, PowerShell download-cradles, decode-and-exec, and
# TLS-bypass patterns that ecosystem scanners can't see. Same Docker semgrep
# image, mounting the rig's bundled ruleset read-only.
RISKY_RULES="$RIG_ROOT/semgrep/legionforge-risky-exec.yml"
if [[ -f "$RISKY_RULES" ]]; then
    if docker_available; then
        WIN_RIG_SEMGREP=$(cygpath -m "$RIG_ROOT/semgrep" 2>/dev/null || echo "$RIG_ROOT/semgrep")
        run_tool "risky-exec" env MSYS_NO_PATHCONV=1 docker run --rm \
            -v "${WIN_PROJECT}:/src" \
            -v "${WIN_RIG_SEMGREP}:/rules:ro" \
            semgrep/semgrep \
            semgrep --config /rules/legionforge-risky-exec.yml /src --error \
            --exclude .claude --exclude .git --exclude node_modules --exclude semgrep
    else
        skip_tool "risky-exec" "docker unavailable — skipping containerized risky-exec rules"
    fi
else
    skip_tool "risky-exec" "custom risky-exec ruleset not found — skipping"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

section "Summary"
failed=0
skipped=0
for result in "${RESULTS[@]}"; do
    tool="${result%%::*}"
    status="${result##*::}"
    if [[ "$status" == "PASS" ]]; then
        echo -e "  ${GREEN}✓  $tool${RESET}"
    elif [[ "$status" == "SKIP" ]]; then
        echo -e "  ${GRAY}-  $tool (skipped)${RESET}"
        ((skipped++)) || true
    else
        echo -e "  ${RED}✗  $tool${RESET}"
        ((failed++)) || true
    fi
done

echo ""
if [[ $failed -eq 0 ]]; then
    echo -e "  ${GREEN}All applicable tools passed.${RESET}"
    [[ $skipped -gt 0 ]] && echo -e "  ${GRAY}$skipped tool(s) skipped as not applicable or unavailable.${RESET}"
    exit 0
else
    echo -e "  ${RED}$failed tool(s) failed.${RESET}"
    exit 1
fi
