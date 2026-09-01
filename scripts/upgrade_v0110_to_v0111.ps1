$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    throw "Existing ThreatLens virtual environment not found. Use scripts\setup.ps1 for a fresh install."
}

.\.venv\Scripts\Activate.ps1

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupRoot = Join-Path (Split-Path $projectRoot -Parent) "ThreatLensAI_v0111_upgrade_backups\$timestamp"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

foreach ($relative in @(".env", "database\threatlens.db")) {
    $source = Join-Path $projectRoot $relative
    if (Test-Path $source) {
        $destination = Join-Path $backupRoot $relative
        New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
        Copy-Item $source $destination -Force
    }
}

$ragRuntime = Join-Path $projectRoot "data\rag"
if (Test-Path $ragRuntime) {
    $ragBackup = Join-Path $backupRoot "rag_runtime_v0110"
    Move-Item $ragRuntime $ragBackup
}
New-Item -ItemType Directory -Path $ragRuntime -Force | Out-Null

Write-Host "Removing the retired ChromaDB package from the existing environment..." -ForegroundColor Cyan
python -m pip uninstall -y chromadb

Write-Host "Installing v0.11.1 reviewed dependencies..." -ForegroundColor Cyan
python -m pip install -r requirements.txt -c constraints-windows-py311.txt
python -m pip install -r requirements-dev.txt -c constraints-windows-py311.txt
python -m pip install -c constraints-windows-py311.txt --no-build-isolation -e .
python -m pip check

python -m scripts.apply_v011_adaptive_profile
python -m scripts.verify_dependency_security --installed
python -m scripts.generate_dependency_attestation
alembic upgrade head

Write-Host "Rebuilding governed knowledge into the built-in SQLite vector store..." -ForegroundColor Cyan
python -m scripts.index_rag_knowledge --force
python -m scripts.verify_rag_runtime --require-ready

Write-Host "ThreatLens AI v0.11.1 upgrade completed." -ForegroundColor Green
Write-Host "Backup: $backupRoot"
