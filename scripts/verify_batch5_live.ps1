
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch5.local"
if (-not (Test-Path $envFile)) { throw ".env.batch5.local does not exist." }

Write-Host "" 
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "THREATLENS BATCH 5 LIVE ACCEPTANCE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "[1/5] Container state..." -ForegroundColor Yellow
docker compose --env-file $envFile -f compose.batch5.yml ps
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect Batch 5 containers." }

Write-Host "[2/5] PostgreSQL + pgvector..." -ForegroundColor Yellow
docker compose --env-file $envFile -f compose.batch5.yml exec -T api python -m scripts.verify_batch5_postgres
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL/pgvector acceptance failed." }

Write-Host "[3/5] Redis..." -ForegroundColor Yellow
$redisPass = (Get-Content $envFile | Where-Object { $_ -like 'THREATLENS_REDIS_PASSWORD=*' }) -replace '^THREATLENS_REDIS_PASSWORD=', ''
docker compose --env-file $envFile -f compose.batch5.yml exec -T redis redis-cli -a $redisPass ping
if ($LASTEXITCODE -ne 0) { throw "Redis acceptance failed." }

Write-Host "[4/5] API readiness + worker presence..." -ForegroundColor Yellow
$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/health/ready" -TimeoutSec 15
$ready | ConvertTo-Json -Depth 8
if ($ready.status -ne "ready") { throw "ThreatLens API is not ready." }
if (-not $ready.async_jobs.reachable) { throw "Redis queue is not reachable through the API." }
if ([int]$ready.async_jobs.workers -lt 1) { throw "No ThreatLens AI worker heartbeat is visible." }

Write-Host "[5/5] Alembic head..." -ForegroundColor Yellow
docker compose --env-file $envFile -f compose.batch5.yml exec -T api python -m alembic current
if ($LASTEXITCODE -ne 0) { throw "Alembic current failed." }

Write-Host "" 
Write-Host "============================================================" -ForegroundColor Green
Write-Host "THREATLENS BATCH 5 LIVE INFRASTRUCTURE: PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Next: sign in at http://127.0.0.1:8080 and perform the async AI-job UAT." -ForegroundColor Cyan
