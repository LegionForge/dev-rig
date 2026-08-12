<#
.SYNOPSIS
    LegionForge audit harness — ruff, bandit, mypy, pip-audit, osv-scanner,
    shellcheck, semgrep, and the custom risky-exec supply-chain ruleset.

.DESCRIPTION
    Runs the static-analysis and security tools against a project directory.
    Native tools (ruff/bandit/mypy/pip-audit) run directly via py -3.13.
    osv-scanner (multi-ecosystem dependency + malicious-package scan) and
    shellcheck run as native binaries; both self-skip when absent.
    Semgrep and the custom risky-exec ruleset run via Docker to avoid
    Windows/Python 3.13+ build failures.

    Per-project configuration lives in two small files at the project root:
      .audit-dirs       — space-separated source dirs (e.g. "llm_valet svcmgr")
      .semgrep-configs  — space-separated semgrep rulesets (e.g. "p/python p/fastapi")

    These mirror the inputs accepted by dev-rig's sast.yml CI workflow so local
    and CI runs stay in sync.

.PARAMETER ProjectPath
    Root directory of the project to audit. Defaults to the current directory.

.EXAMPLE
    # From the project root:
    & "D:\Info2\Working\Claude\projects\LegionForge-dev-rig\dev-rig\scripts\audit.ps1"

    # From anywhere:
    & "D:\...\dev-rig\scripts\audit.ps1" -ProjectPath "D:\...\llm-valet"
#>

[CmdletBinding()]
param(
    [string]$ProjectPath = $PWD
)

$ProjectPath = (Resolve-Path $ProjectPath).Path

# Dev-rig root (this script lives in <rig>/scripts/) — locates the bundled
# custom Semgrep ruleset regardless of the consuming project's CWD.
$RigRoot = Split-Path $PSScriptRoot -Parent

# ── Read per-project config ───────────────────────────────────────────────────

# Which source directories to scan (ruff / bandit / mypy / semgrep).
# Add a .audit-dirs file to the project root to override.
$auditDirsFile = Join-Path $ProjectPath ".audit-dirs"
$SourceDirs = if (Test-Path $auditDirsFile) {
    (Get-Content $auditDirsFile -Raw).Trim()
} else {
    "."
}

# Which semgrep rule packs to run.
# Add a .semgrep-configs file to the project root to override.
$semgrepConfigsFile = Join-Path $ProjectPath ".semgrep-configs"
$SemgrepConfigs = if (Test-Path $semgrepConfigsFile) {
    (Get-Content $semgrepConfigsFile -Raw).Trim()
} else {
    "p/python"
}

$sourceDirList = $SourceDirs -split '\s+'

# ── Output helpers ────────────────────────────────────────────────────────────

$results = [ordered]@{}

function Write-Section([string]$title) {
    $line = "─" * [Math]::Max(1, 62 - $title.Length)
    Write-Host "`n── $title $line" -ForegroundColor DarkGray
}

function Invoke-Tool([string]$name, [scriptblock]$cmd) {
    Write-Section $name
    Push-Location $ProjectPath
    try {
        & $cmd
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($code -eq 0) {
        Write-Host "  ✓  $name passed" -ForegroundColor Green
        $results[$name] = "PASS"
    } else {
        Write-Host "  ✗  $name FAILED  (exit $code)" -ForegroundColor Red
        $results[$name] = "FAIL"
    }
}

# ── Header ────────────────────────────────────────────────────────────────────

Write-Host "`nLegionForge Audit Harness" -ForegroundColor Cyan
Write-Host "  Project : $ProjectPath"
Write-Host "  Dirs    : $SourceDirs"
Write-Host "  Semgrep : $SemgrepConfigs"

# ── ruff — style, imports, antipatterns ──────────────────────────────────────

Invoke-Tool "ruff" {
    py -3.13 -m ruff check @sourceDirList
}

# ── bandit — Python security smells ──────────────────────────────────────────

Invoke-Tool "bandit" {
    $args = @("-r") + $sourceDirList + @("-q")
    # Use pyproject.toml config if present (skips reviewed subprocess warnings etc.)
    if (Test-Path (Join-Path $ProjectPath "pyproject.toml")) {
        $args += @("-c", "pyproject.toml")
    }
    py -3.13 -m bandit @args
}

# ── mypy — type correctness ───────────────────────────────────────────────────

Invoke-Tool "mypy" {
    py -3.13 -m mypy @sourceDirList
}

# ── pip-audit — dependency CVE scan ──────────────────────────────────────────
# The "." argument scopes audit to this project's declared deps only.
# Never run without "." on a global Python — you'll get noise from every
# system package (Anaconda, conda, etc.).

Invoke-Tool "pip-audit" {
    py -3.13 -m pip_audit .
}

# ── osv-scanner — multi-ecosystem dependency + malicious-package scan ─────────
# One pass over every lockfile (Python / npm / Cargo / …), checked against OSV
# (CVEs + malicious-packages feed). --allow-no-lockfiles: nothing to scan is a
# pass, not a failure. Self-skips when the binary isn't installed.

if (Get-Command osv-scanner -ErrorAction SilentlyContinue) {
    Invoke-Tool "osv-scanner" {
        osv-scanner scan source --recursive --allow-no-lockfiles .
    }
} else {
    Write-Section "osv-scanner"
    Write-Host "  osv-scanner not installed — skipping (winget install Google.osv-scanner)" -ForegroundColor DarkGray
}

# ── shellcheck — shell script correctness + footguns ─────────────────────────
# Runs only when the repo contains shell scripts.

$shellFiles = Get-ChildItem -Path $ProjectPath -Recurse -File -Include *.sh, *.bash -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '[\\/](\.git|\.venv|node_modules|\.claude)[\\/]' }
if ($shellFiles) {
    if (Get-Command shellcheck -ErrorAction SilentlyContinue) {
        Invoke-Tool "shellcheck" {
            shellcheck @($shellFiles.FullName)
        }
    } else {
        Write-Section "shellcheck"
        Write-Host "  $($shellFiles.Count) shell script(s) found but shellcheck not installed — skipping" -ForegroundColor DarkGray
    }
}

# ── semgrep — OWASP / framework-specific vulnerability patterns ───────────────
# Runs inside the official Docker image to avoid Windows/Python 3.13 build issues.
# First run pulls the image (~200 MB); subsequent runs use the local cache.
# Mirrors sast.yml CI workflow — same configs, same source dirs, --error flag.

Invoke-Tool "semgrep" {
    $dockerArgs = @(
        "run", "--rm",
        "-v", "${ProjectPath}:/src",
        "semgrep/semgrep",
        "semgrep"
    )
    foreach ($cfg in ($SemgrepConfigs -split '\s+')) {
        $dockerArgs += "--config=$cfg"
    }
    foreach ($dir in $sourceDirList) {
        $dockerArgs += "/src/$dir"
    }
    $dockerArgs += "--error"
    & docker @dockerArgs
}

# ── risky-exec — LegionForge custom supply-chain / RCE pattern rules ──────────
# Flags curl|bash installers, PowerShell download-cradles, decode-and-exec, and
# TLS-bypass patterns ecosystem scanners can't see. Same Docker semgrep image,
# mounting the rig's bundled ruleset read-only.

$riskyRules = Join-Path $RigRoot "semgrep/legionforge-risky-exec.yml"
if (Test-Path $riskyRules) {
    Invoke-Tool "risky-exec" {
        $rigSemgrep = Join-Path $RigRoot "semgrep"
        & docker run --rm `
            -v "${ProjectPath}:/src" `
            -v "${rigSemgrep}:/rules:ro" `
            semgrep/semgrep `
            semgrep --config /rules/legionforge-risky-exec.yml /src --error `
            --exclude .claude --exclude .git --exclude node_modules --exclude semgrep
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Section "Summary"
$failed = 0
foreach ($tool in $results.Keys) {
    if ($results[$tool] -eq "PASS") {
        Write-Host "  ✓  $tool" -ForegroundColor Green
    } else {
        Write-Host "  ✗  $tool" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
if ($failed -eq 0) {
    Write-Host "  All tools passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  $failed tool(s) failed." -ForegroundColor Red
    exit 1
}
