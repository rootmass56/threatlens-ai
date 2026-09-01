$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Help)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $Help"
    }
}

Write-Host "" 
Write-Host "ThreatLens AI v0.12.0 Production Web RC - Windows Install + Full Verification" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"

Assert-Command -Name "npm" -Help "Install the current Node.js LTS release before continuing."
Assert-Command -Name "node" -Help "Install the current Node.js LTS release before continuing."

$nodeVersionText = (node --version).Trim().TrimStart('v')
$nodeVersion = [version]$nodeVersionText
if (($nodeVersion.Major -lt 22) -or ($nodeVersion.Major -eq 22 -and $nodeVersion -lt [version]"22.12.0")) {
    throw "Vite 8 requires Node.js 20.19+ or 22.12+. ThreatLens recommends current Node.js LTS; detected $nodeVersionText."
}
Write-Host "Node.js: v$nodeVersionText" -ForegroundColor Green
Write-Host "npm: $(npm --version)" -ForegroundColor Green

if (-not (Get-Command "ollama" -ErrorAction SilentlyContinue)) {
    throw "Ollama is required for the complete local RAG verification gate. Install Ollama and rerun this script."
}
Write-Host "Ollama: available" -ForegroundColor Green

# A final RC verification must not silently skip either dependency security or live RAG readiness.
$env:THREATLENS_REQUIRE_ONLINE_DEPENDENCY_AUDIT = "1"
$env:THREATLENS_REQUIRE_RAG_READY = "1"

Write-Host "" 
Write-Host "[1/4] Creating/verifying the Python 3.11 environment, database, ATT&CK catalogs and local Qwen models..." -ForegroundColor Cyan
& .\scripts\setup.ps1
if ($LASTEXITCODE -ne 0) { throw "ThreatLens setup failed." }

Write-Host "" 
Write-Host "[2/4] Resolving the frontend dependency graph and creating the reproducible package-lock.json..." -ForegroundColor Cyan
Push-Location frontend
try {
    npm install --package-lock-only --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw "Frontend package-lock generation failed." }
}
finally { Pop-Location }

Write-Host ""
Write-Host "[3/4] Generating the v0.12.0 release manifest from the exact RC tree..." -ForegroundColor Cyan
python -m scripts.generate_release_manifest
if ($LASTEXITCODE -ne 0) { throw "ThreatLens v0.12.0 release manifest generation failed." }

Write-Host ""
Write-Host "[4/4] Running the complete v0.12.0 release gate, including 271 governed Windows tests and the React build/audit..." -ForegroundColor Cyan
& .\scripts\verify.ps1
if ($LASTEXITCODE -ne 0) { throw "ThreatLens verification failed." }

Write-Host "" 
Write-Host "============================================================" -ForegroundColor Green
Write-Host "ThreatLens AI v0.12.0 LOCAL RELEASE-CANDIDATE GATE: PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Bootstrap credentials (first setup only): data\bootstrap_admin_credentials.txt" -ForegroundColor Yellow
Write-Host "Delete that credential file after recording the password securely." -ForegroundColor Yellow
Write-Host "Next: run local feature-parity UAT and operational-data migration before deployment. See docs\FEATURE_PARITY_v0.12.md." -ForegroundColor Cyan
