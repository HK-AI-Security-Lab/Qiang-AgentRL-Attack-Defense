# CyberGym pipeline launcher (Windows PowerShell)
# Usage:
#   .\run.ps1                  # full pipeline (uses cached capability table)
#   .\run.ps1 fresh            # rerun Base Model first, then pipeline
#   .\run.ps1 graph            # open the latest attack_graph.html
#   .\run.ps1 report           # open the latest report.md

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('demo', 'fresh', 'graph', 'report', 'translate', 'install')]
    [string]$Command = 'demo'
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# Reuse the parent project's venv so we don't double-install everything.
$VenvPython = "..\.venv\Scripts\python.exe"

function Write-Step($msg)  { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Err2($msg)  { Write-Host "    [X]  $msg" -ForegroundColor Red }

function Use-Venv {
    if (-not (Test-Path $VenvPython)) {
        Write-Err2 "venv not found at $VenvPython. Run the parent project's .\run.ps1 install first."
        exit 1
    }
}

function Test-PythonImport($module) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $VenvPython -c "import $module" 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally { $ErrorActionPreference = $prev }
}

function Install-Deps {
    Use-Venv
    Write-Step 'Installing CyberGym deps (networkx, pyyaml)'
    & $VenvPython -m pip install -q networkx pyyaml
    if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
    Write-Ok 'deps OK'
}

function Run-Pipeline([bool]$translate) {
    Use-Venv
    if (-not (Test-PythonImport 'networkx')) { Install-Deps }

    if ($translate) {
        Write-Step 'Running pipeline (Base Model translate + Harness)'
        & $VenvPython -m scripts.pipeline --translate
    } else {
        Write-Step 'Running pipeline (cached capability table)'
        & $VenvPython -m scripts.pipeline
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Ok 'done. Open out\attack_graph.html to inspect.'
}

function Run-Translate {
    Use-Venv
    if (-not (Test-PythonImport 'openai')) {
        Write-Err2 'openai package not in venv. Run parent install first.'
        exit 1
    }
    Write-Step 'Running Base Model translate only'
    & $VenvPython -m base_model.translate data\sample_tasks.json -n 8 -o data\capability_table.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Ok 'capability_table.json updated.'
}

function Open-File($path) {
    if (Test-Path $path) {
        Write-Ok "opening $path"
        Start-Process $path
    } else {
        Write-Err2 "$path not found. Run .\run.ps1 first."
        exit 1
    }
}

switch ($Command) {
    'install'   { Install-Deps }
    'translate' { Run-Translate }
    'demo'      { Run-Pipeline $false }
    'fresh'     { Run-Pipeline $true }
    'graph'     { Open-File 'out\attack_graph.html' }
    'report'    { Open-File 'out\report.md' }
}
