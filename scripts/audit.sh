#!/usr/bin/env bash
# LegionForge audit harness.
#   Python  : ruff, bandit, mypy, pip-audit
#   All deps: osv-scanner (Python / npm / Cargo / … vulns + malicious packages)
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

declare -A RESULTS
declare -a ORDER=()   # preserves run order for the summary (assoc arrays don't)

section() { echo -e "\n${GRAY}── $1 $(printf '─%.0s' $(seq 1 $((62 - ${#1}))))${RESET}"; }

run_tool() {
    local name="$1"
    shift
    section "$name"
    ORDER+=("$name")
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

# ── osv-scanner — multi-ecosystem dependency + malicious-package scan ──────────
# One pass over every lockfile in the repo (Python / npm / Cargo / Go / …),
# checked against the OSV database — CVEs *and* the malicious-packages feed that
# pip-audit lacks. --allow-no-lockfiles makes a repo with nothing to scan a pass,
# not a failure, so the harness stays usable everywhere.
if command -v osv-scanner > /dev/null 2>&1; then
    run_tool "osv-scanner" osv-scanner scan source --recursive --allow-no-lockfiles .
else
    section "osv-scanner"
    echo -e "  ${GRAY}osv-scanner not installed — skipping (brew install osv-scanner)${RESET}"
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
        section "shellcheck"
        echo -e "  ${GRAY}${#shell_files[@]} shell script(s) found but shellcheck not installed — skipping (brew install shellcheck)${RESET}"
    fi
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
run_tool "semgrep" env MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${WIN_PROJECT}:/src" \
    semgrep/semgrep \
    semgrep "${semgrep_args[@]}"

# ── risky-exec — LegionForge custom supply-chain / RCE pattern rules ───────────
# Flags curl|bash installers, PowerShell download-cradles, decode-and-exec, and
# TLS-bypass patterns that ecosystem scanners can't see. Same Docker semgrep
# image, mounting the rig's bundled ruleset read-only.
RISKY_RULES="$RIG_ROOT/semgrep/legionforge-risky-exec.yml"
if [[ -f "$RISKY_RULES" ]]; then
    WIN_RIG_SEMGREP=$(cygpath -m "$RIG_ROOT/semgrep" 2>/dev/null || echo "$RIG_ROOT/semgrep")
    run_tool "risky-exec" env MSYS_NO_PATHCONV=1 docker run --rm \
        -v "${WIN_PROJECT}:/src" \
        -v "${WIN_RIG_SEMGREP}:/rules:ro" \
        semgrep/semgrep \
        semgrep --config /rules/legionforge-risky-exec.yml /src --error \
        --exclude .claude --exclude .git --exclude node_modules --exclude semgrep
fi

# ── Summary ───────────────────────────────────────────────────────────────────

section "Summary"
failed=0
for tool in "${ORDER[@]}"; do
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
