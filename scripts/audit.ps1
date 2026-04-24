<#
.SYNOPSIS
    LegionForge audit harness — ruff, bandit, mypy, pip-audit, semgrep.

.DESCRIPTION
    Runs all five static-analysis and security tools against a project directory.
    Native tools (ruff/bandit/mypy/pip-audit) run directly via py -3.13.
    Semgrep runs via Docker to avoid Windows/Python 3.13+ build failures.

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
