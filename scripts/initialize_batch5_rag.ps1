
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch5.local"
if (-not (Test-Path $envFile)) { throw ".env.batch5.local does not exist." }

Write-Host "Rebuilding governed ThreatLens knowledge into PostgreSQL/pgvector..." -ForegroundColor Cyan
docker compose --env-file $envFile -f compose.batch5.yml exec -T api python -m scripts.index_rag_knowledge --force
if ($LASTEXITCODE -ne 0) { throw "Batch 5 pgvector knowledge indexing failed." }

docker compose --env-file $envFile -f compose.batch5.yml exec -T api python -m scripts.verify_batch5_postgres
if ($LASTEXITCODE -ne 0) { throw "Batch 5 pgvector verification failed." }

Write-Host "BATCH 5 PGVECTOR KNOWLEDGE INITIALIZATION: PASS" -ForegroundColor Green
