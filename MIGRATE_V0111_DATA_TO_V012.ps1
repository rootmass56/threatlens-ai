param(
    [string]$SourceDatabase,
    [switch]$Apply,
    [switch]$ReplaceOperationalData
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$target = Join-Path $projectRoot "database\threatlens.db"

if ([string]::IsNullOrWhiteSpace($SourceDatabase)) {
    $SourceDatabase = Join-Path (Split-Path $projectRoot -Parent) "ThreatLensAI_v0.11.1_FINAL\database\threatlens.db"
}

if (-not (Test-Path $python)) {
    throw "ThreatLens v0.12 virtual environment is missing. Run INSTALL_THREATLENS_V012_AND_VERIFY.ps1 first."
}
if (-not (Test-Path $SourceDatabase)) {
    throw "v0.11.1 source database was not found: $SourceDatabase"
}
if (-not (Test-Path $target)) {
    throw "v0.12 target database was not found: $target"
}

Write-Host "" 
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "THREATLENS AI v0.11.1 -> v0.12 OPERATIONAL DATA MIGRATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Source: $SourceDatabase"
Write-Host "Target: $target"
Write-Host ""
Write-Host "Security identity is NOT imported: users, password hashes, roles, refresh tokens and login attempts stay owned by v0.12." -ForegroundColor Yellow
Write-Host ""

$arguments = @(
    "-m", "scripts.migrate_v0111_operational_data",
    "--source", $SourceDatabase,
    "--target", $target
)

if (-not $Apply) {
    $arguments += "--dry-run"
    Write-Host "DRY RUN ONLY. No database will be modified." -ForegroundColor Yellow
}
elseif ($ReplaceOperationalData) {
    $arguments += "--replace-operational-data"
    Write-Host "APPLY MODE: existing v0.12 operational SOC data may be replaced after an automatic backup." -ForegroundColor Yellow
}
else {
    Write-Host "APPLY MODE: migration will proceed only if the v0.12 operational tables are empty." -ForegroundColor Yellow
}

& $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "ThreatLens operational data migration failed."
}

if (-not $Apply) {
    Write-Host ""
    Write-Host "Dry-run validation passed. Review the counts above." -ForegroundColor Green
    Write-Host "To apply to an empty v0.12 operational database:" -ForegroundColor Cyan
    Write-Host ".\MIGRATE_V0111_DATA_TO_V012.ps1 -Apply"
    Write-Host ""
    Write-Host "If v0.12 already contains disposable UAT operational data and you deliberately want to replace it:" -ForegroundColor Cyan
    Write-Host ".\MIGRATE_V0111_DATA_TO_V012.ps1 -Apply -ReplaceOperationalData"
}
else {
    Write-Host ""
    Write-Host "Operational data migration completed. Restart the FastAPI process before UAT." -ForegroundColor Green
}
