$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $project

function Require-Command {
    param([Parameter(Mandatory=$true)][string]$Name,[string]$Message="")
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $Message"
    }
}

Write-Host "" 
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "THREATLENS AI v0.14.0 - BATCH 7 INSTALL + STATIC ACCEPTANCE" -ForegroundColor Cyan
Write-Host "===================================================================="

Require-Command "py" "Install CPython 3.11 with the Windows py launcher."
Require-Command "docker.exe" "Start Docker Desktop before the Docker validation stage."
Require-Command "node.exe" "Install a current Node.js LTS release."
Require-Command "npm.cmd" "Install a current Node.js LTS release."

Write-Host "[1/6] Verifying Python 3.11..." -ForegroundColor Yellow
$versionRaw = & py -3.11 -c "import sys; print('.'.join(map(str,sys.version_info[:3])))"
if ($LASTEXITCODE -ne 0) { throw "Python 3.11 is not available." }
$version = ([string]$versionRaw).Trim()
if (-not $version.StartsWith("3.11.")) { throw "Expected Python 3.11, got $version" }
Write-Host "[OK] Python $version" -ForegroundColor Green

$venv = Join-Path $project ".venv"
$python = Join-Path $venv "Scripts\python.exe"

Write-Host "[2/6] Creating/updating isolated Batch-7 virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path -LiteralPath $python)) {
    & py -3.11 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create .venv." }
}
& $python -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0" "wheel==0.47.0"
if ($LASTEXITCODE -ne 0) { throw "Build-tool installation failed." }
& $python -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw "ThreatLens Batch-7 Python dependency installation failed." }
Write-Host "[OK] Python environment ready." -ForegroundColor Green

Write-Host "[3/6] Creating ignored Batch-7 local secrets..." -ForegroundColor Yellow
& (Join-Path $project "scripts\bootstrap_batch7_env.ps1")
if ($LASTEXITCODE -ne 0) { throw "Batch-7 environment bootstrap failed." }
Write-Host "[OK] .env.batch7.local ready." -ForegroundColor Green

Write-Host "[4/6] Running Python/Batch-7 release contract..." -ForegroundColor Yellow
$env:THREATLENS_JWT_SECRET = "batch7-install-static-secret-that-is-long-enough-123456789"
& $python -m compileall -q api database jobs rag scripts advanced_soc core app correlation attack ops migrations
if ($LASTEXITCODE -ne 0) { throw "Python compile gate failed." }
& $python -m scripts.verify_batch7_release
if ($LASTEXITCODE -ne 0) { throw "Batch-7 release contract failed." }
& $python -m pytest -q tests/test_batch7_operational_hardening.py
if ($LASTEXITCODE -ne 0) { throw "Batch-7 focused tests failed." }
Write-Host "[OK] Batch-7 Python release contract PASS." -ForegroundColor Green

Write-Host "[5/6] Installing/verifying frontend..." -ForegroundColor Yellow
Push-Location (Join-Path $project "frontend")
try {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
    & npm.cmd run typecheck
    if ($LASTEXITCODE -ne 0) { throw "Frontend typecheck failed." }
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "Frontend production build failed." }
}
finally { Pop-Location }
Write-Host "[OK] Frontend build PASS." -ForegroundColor Green

Write-Host "[6/6] Validating Batch-7 Docker Compose including observability profile..." -ForegroundColor Yellow
$envFile = Join-Path $project ".env.batch7.local"
& docker.exe compose --profile observability --env-file $envFile -f (Join-Path $project "compose.batch7.yml") config --quiet
if ($LASTEXITCODE -ne 0) { throw "Batch-7 Compose validation failed." }
Write-Host "[OK] Docker Compose contract PASS." -ForegroundColor Green

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "THREATLENS BATCH 7 INSTALL + STATIC ACCEPTANCE: PASS" -ForegroundColor Green
Write-Host "===================================================================="
Write-Host "NEXT: scripts\MIGRATE_BATCH6_DATA_TO_BATCH7.ps1 -StartObservability" -ForegroundColor Cyan
