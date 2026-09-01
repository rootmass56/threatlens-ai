param(
    [string]$SourceDatabase,
    [switch]$ApplyMigration,
    [switch]$ReplaceOperationalData,
    [switch]$LaunchUAT
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "THREATLENS AI v0.12 - FULL FEATURE-PARITY PHASE GATE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"
Write-Host ""

# The full installer is the authoritative Windows release gate. It creates the
# Python 3.11 environment, resolves the npm lockfile, generates the manifest and
# runs all 271 governed Windows tests plus the React/Vite/security checks.
& .\INSTALL_THREATLENS_V012_AND_VERIFY.ps1
if ($LASTEXITCODE -ne 0) {
    throw "ThreatLens full Windows release gate failed."
}

python -m scripts.verify_frontend_feature_parity
if ($LASTEXITCODE -ne 0) {
    throw "Streamlit-to-React feature-parity verification failed."
}

if ([string]::IsNullOrWhiteSpace($SourceDatabase)) {
    $candidate = Join-Path (Split-Path $projectRoot -Parent) "ThreatLensAI_v0.11.1_FINAL\database\threatlens.db"
    if (Test-Path $candidate) {
        $SourceDatabase = $candidate
    }
}

if (-not [string]::IsNullOrWhiteSpace($SourceDatabase)) {
    if (-not (Test-Path $SourceDatabase)) {
        throw "Requested v0.11.1 source database was not found: $SourceDatabase"
    }

    Write-Host ""
    Write-Host "Running guarded operational-data migration validation..." -ForegroundColor Cyan
    $migrationArgs = @{ SourceDatabase = $SourceDatabase }
    if ($ApplyMigration) { $migrationArgs.Apply = $true }
    if ($ReplaceOperationalData) { $migrationArgs.ReplaceOperationalData = $true }
    & .\MIGRATE_V0111_DATA_TO_V012.ps1 @migrationArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Operational-data migration gate failed."
    }
}
else {
    Write-Host "No v0.11.1 operational database was supplied/discovered; migration is consciously waived for this run." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "AUTOMATED FEATURE-PARITY GATES: PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Next mandatory step: complete the interactive React UAT checklist." -ForegroundColor Yellow
Write-Host "Run: .\RUN_THREATLENS_V012_UAT.ps1" -ForegroundColor Cyan
Write-Host "Then: .\RECORD_FEATURE_PARITY_UAT.ps1" -ForegroundColor Cyan

if ($LaunchUAT) {
    & .\RUN_THREATLENS_V012_UAT.ps1
}
