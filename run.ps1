# AutoPatch-RL Demo - Windows PowerShell launcher
# Usage:
#   .\run.ps1               # single-side demo (blue defender loop)
#   .\run.ps1 battle        # red vs blue adversarial demo
#   .\run.ps1 report        # open latest report.md
#   .\run.ps1 down          # stop target container
#   .\run.ps1 clean         # wipe generated + runs

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('demo', 'battle', 'report', 'graph', 'down', 'clean', 'install', 'build')]
    [string]$Command = 'demo'
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    [!]  $msg" -ForegroundColor Yellow }
function Write-Err2($msg)  { Write-Host "    [X]  $msg" -ForegroundColor Red }

function Assert-Tool($exe, $hint) {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        Write-Err2 "Missing '$exe'. $hint"
        exit 1
    }
}

function Ensure-Venv {
    if (-not (Test-Path '.venv\Scripts\python.exe')) {
        Write-Step 'Creating venv at .venv'
        Assert-Tool 'python' 'Install Python >= 3.9 and add it to PATH'
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
    }
}

function Use-Venv {
    Ensure-Venv
    $env:VIRTUAL_ENV = (Resolve-Path '.venv').Path
    $env:PATH = "$env:VIRTUAL_ENV\Scripts;$env:PATH"
}

function Install-Deps {
    Use-Venv
    Write-Step 'Installing deps via pip install -e .'
    & .\.venv\Scripts\python.exe -m pip install -U pip | Out-Null
    & .\.venv\Scripts\python.exe -m pip install -e .
    if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
    Write-Ok 'deps installed'
}

function Test-PythonImport($module) {
    # Native stderr (Traceback) under EAP=Stop would terminate the script,
    # so locally relax EAP and rely on $LASTEXITCODE for the real signal.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & .\.venv\Scripts\python.exe -c "import $module" 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Check-Docker {
    Write-Step 'Checking Docker'
    Assert-Tool 'docker' 'Install and start Docker Desktop'
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Err2 'Docker daemon not running. Start Docker Desktop and retry.'
        exit 1
    }
    Write-Ok 'Docker OK'
}

function Check-Bash {
    Write-Step 'Checking bash (probe scripts and docker_run.sh need a real POSIX bash, not WSL launcher)'
    $candidates = @(
        'C:\Program Files\Git\bin\bash.exe',
        'C:\Program Files (x86)\Git\bin\bash.exe',
        "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
    )
    $gitBash = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    $current = (Get-Command 'bash' -ErrorAction SilentlyContinue).Source
    $isWslBash = $current -and ($current -like '*\System32\bash.exe' -or $current -like '*\WindowsApps\*')

    if ($gitBash) {
        $gitBashDir = Split-Path -Parent $gitBash
        # Always prepend Git Bash so it wins over the WSL launcher.
        $env:PATH = "$gitBashDir;$env:PATH"
        Write-Ok "Using Git Bash: $gitBash"
        if ($isWslBash) {
            Write-Warn2 "WSL bash ($current) was on PATH first; overridden for this session."
        }
    } elseif ($isWslBash) {
        Write-Err2 "Only the WSL bash launcher is on PATH ($current), and it has no WSL distro behind it. Install Git for Windows."
        exit 1
    } elseif ($current) {
        Write-Ok "bash available: $current"
    } else {
        Write-Err2 "bash not found. Install Git for Windows."
        exit 1
    }
}

function Check-Env {
    Write-Step 'Checking .env'
    if (-not (Test-Path '.env')) {
        Write-Err2 '.env missing. Create it with OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_MODEL.'
        exit 1
    }
    $envText = Get-Content .env -Raw
    foreach ($k in 'OPENAI_API_KEY','OPENAI_BASE_URL','OPENAI_MODEL') {
        if ($envText -notmatch "(?m)^\s*$k\s*=") {
            Write-Warn2 ".env missing $k - agent may fall back to heuristic mode"
        }
    }
    Write-Ok '.env present'
}

function Build-Target {
    Check-Docker
    Write-Step 'Building target image autopatch-target:vuln'
    docker build -t autopatch-target:vuln target/
    if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
    Write-Ok 'image built'
}

function Stop-Target {
    Write-Step 'Stopping target container'
    # docker rm -f writes to stderr if the container doesn't exist; under
    # EAP=Stop that becomes a fatal error. Locally relax it.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        docker rm -f autopatch-target 2>&1 | Out-Null
    } finally {
        $ErrorActionPreference = $prev
    }
    Write-Ok 'cleaned'
}

function Run-Demo {
    Check-Env; Check-Bash; Check-Docker
    Use-Venv
    if (-not (Test-PythonImport 'openai')) { Install-Deps }
    $imgId = (docker images -q autopatch-target:vuln) -join ''
    if (-not $imgId) { Build-Target }

    Write-Step 'Running single-side demo: python -m core.orchestrator'
    & .\.venv\Scripts\python.exe -m core.orchestrator
    $code = $LASTEXITCODE
    Stop-Target
    exit $code
}

function Run-Battle {
    Check-Env; Check-Bash; Check-Docker
    Use-Venv
    if (-not (Test-PythonImport 'openai')) { Install-Deps }
    $imgId = (docker images -q autopatch-target:vuln) -join ''
    if (-not $imgId) { Build-Target }

    Write-Step 'Running red-vs-blue demo: python -m core.adversarial'
    & .\.venv\Scripts\python.exe -m core.adversarial
    $code = $LASTEXITCODE
    Stop-Target
    exit $code
}

function Open-Report {
    if (-not (Test-Path 'reports\runs')) {
        Write-Err2 'no run records yet'
        exit 1
    }
    $latest = Get-ChildItem 'reports\runs' -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        Write-Err2 'no run records yet'
        exit 1
    }
    $report = Join-Path $latest.FullName 'report.md'
    if (Test-Path $report) {
        Write-Ok "opening $report"
        Start-Process $report
    } else {
        Write-Warn2 "$report not found"
    }
}

function Open-Graph {
    if (-not (Test-Path 'reports\runs')) {
        Write-Err2 'no run records yet'
        exit 1
    }
    $latest = Get-ChildItem 'reports\runs' -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        Write-Err2 'no run records yet'
        exit 1
    }
    $graph = Join-Path $latest.FullName 'attack_graph.html'
    if (Test-Path $graph) {
        Write-Ok "opening $graph"
        Start-Process $graph
    } else {
        Write-Warn2 "$graph not found (try .\run.ps1 demo first)"
    }
}

function Clean-All {
    Stop-Target
    Write-Step 'Wiping policies\generated and reports\runs'
    if (Test-Path 'policies\generated') { Get-ChildItem 'policies\generated' -Force | Remove-Item -Recurse -Force }
    if (Test-Path 'reports\runs')       { Get-ChildItem 'reports\runs' -Force       | Remove-Item -Recurse -Force }
    Write-Ok 'done'
}

switch ($Command) {
    'install' { Install-Deps }
    'build'   { Build-Target }
    'demo'    { Run-Demo }
    'battle'  { Run-Battle }
    'report'  { Open-Report }
    'graph'   { Open-Graph }
    'down'    { Stop-Target }
    'clean'   { Clean-All }
}
