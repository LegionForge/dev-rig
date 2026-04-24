#!/usr/bin/env bash
# LegionForge audit harness — ruff, bandit, mypy, pip-audit, semgrep.
#
# Usage:
#   ./audit.sh                        # from the project root
#   ./audit.sh /path/to/project       # from anywhere
#
# Per-project config (place at project root):
#   .audit-dirs       — space-separated source dirs  (e.g. "llm_valet svcmgr")
#   .semgrep-configs  — space-separated semgrep rule packs (e.g. "p/python p/fastapi")

set -euo pipefail

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

declare -A RESULTS

section() { echo -e "\n${GRAY}── $1 $(printf '─%.0s' $(seq 1 $((62 - ${#1}))))${RESET}"; }

run_tool() {
    local name="$1"
    shift
    section "$name"
    pushd "$PROJECT" > /dev/null
    if "$@"; then
        echo -e "  ${GREEN}✓  $name passed${RESET}"
        RESULTS[$name]="PASS"
    else
        echo -e "  ${RED}✗  $name FAILED${RESET}"
        RESULTS[$name]="FAIL"
    fi
    popd > /dev/null
}

# ── Header ────────────────────────────────────────────────────────────────────

echo -e "\n${CYAN}LegionForge Audit Harness${RESET}"
echo    "  Project : $PROJECT"
echo    "  Dirs    : $SOURCE_DIRS"
echo    "  Semgrep : $SEMGREP_CONFIGS"

read -ra SOURCE_DIR_LIST <<< "$SOURCE_DIRS"

# ── ruff ──────────────────────────────────────────────────────────────────────

run_tool "ruff" py -3.13 -m ruff check "${SOURCE_DIR_LIST[@]}"

# ── bandit ────────────────────────────────────────────────────────────────────

bandit_args=("-r" "${SOURCE_DIR_LIST[@]}" "-q")
[[ -f "$PROJECT/pyproject.toml" ]] && bandit_args+=("-c" "pyproject.toml")
run_tool "bandit" py -3.13 -m bandit "${bandit_args[@]}"

# ── mypy ──────────────────────────────────────────────────────────────────────

run_tool "mypy" py -3.13 -m mypy "${SOURCE_DIR_LIST[@]}"

# ── pip-audit ─────────────────────────────────────────────────────────────────

run_tool "pip-audit" py -3.13 -m pip_audit .

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
run_tool "semgrep" env MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${WIN_PROJECT}:/src" \
    semgrep/semgrep \
    semgrep "${semgrep_args[@]}"

# ── Summary ───────────────────────────────────────────────────────────────────

section "Summary"
failed=0
for tool in ruff bandit mypy pip-audit semgrep; do
    if [[ "${RESULTS[$tool]}" == "PASS" ]]; then
        echo -e "  ${GREEN}✓  $tool${RESET}"
    else
        echo -e "  ${RED}✗  $tool${RESET}"
        ((failed++)) || true
    fi
done

echo ""
if [[ $failed -eq 0 ]]; then
    echo -e "  ${GREEN}All tools passed.${RESET}"
    exit 0
else
    echo -e "  ${RED}$failed tool(s) failed.${RESET}"
    exit 1
fi
