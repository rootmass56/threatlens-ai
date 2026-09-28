$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch6.local"
if (-not (Test-Path $envFile)) { throw ".env.batch6.local does not exist." }
Write-Host "THREATLENS BATCH 6 LIVE ACCEPTANCE" -ForegroundColor Cyan
docker compose --env-file $envFile -f deploy/compose/legacy/batch6.yml ps
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect Batch-6 containers." }
$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/health/ready" -TimeoutSec 20
if ([string]$ready.status -ne "ready") { throw "API readiness is not READY." }
docker compose --env-file $envFile -f deploy/compose/legacy/batch6.yml exec -T api alembic current
if ($LASTEXITCODE -ne 0) { throw "Alembic current failed." }
$headRaw = docker compose --env-file $envFile -f deploy/compose/legacy/batch6.yml exec -T api alembic heads
$head = ($headRaw | Out-String)
if ($head -notmatch "f6a6c0b60001") { throw "Batch-6 migration head is not active." }
docker compose --env-file $envFile -f deploy/compose/legacy/batch6.yml exec -T api python -m scripts.verify_batch6_release
if ($LASTEXITCODE -ne 0) { throw "Containerized Batch-6 contract failed." }
Write-Host "THREATLENS BATCH 6 LIVE FOUNDATION: PASS" -ForegroundColor Green
Write-Host "Perform browser UAT for 6A-6H before recording the Batch-6 freeze tag." -ForegroundColor Yellow
