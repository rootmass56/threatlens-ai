
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project

$envFile = Join-Path $project ".env.batch5.local"
if (-not (Test-Path $envFile)) {
    & (Join-Path $PSScriptRoot "bootstrap_batch5_env.ps1")
}

Write-Host "Building and starting PostgreSQL/pgvector, Redis, API, worker and React..." -ForegroundColor Cyan
docker compose --env-file $envFile -f deploy/compose/legacy/batch5.yml up --build -d
if ($LASTEXITCODE -ne 0) { throw "Batch 5 stack startup failed." }

Write-Host "" 
Write-Host "ThreatLens Batch 5 stack is starting." -ForegroundColor Green
Write-Host "Frontend : http://127.0.0.1:8080"
Write-Host "API      : proxied through http://127.0.0.1:8080/api/v1/..."
Write-Host ""
Write-Host "Run scripts\verify_batch5_live.ps1 after the containers become healthy." -ForegroundColor Cyan
