param([switch]$RequireObservability)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
if (-not (Test-Path -LiteralPath $envFile)) { throw ".env.batch7.local does not exist." }

Write-Host "THREATLENS BATCH 7 LIVE ACCEPTANCE" -ForegroundColor Cyan

& docker.exe compose --profile observability --env-file $envFile -f $compose ps
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect Batch-7 containers." }

$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/health/ready" -TimeoutSec 20
if ([string]$ready.status -ne "ready") { throw "API readiness is not READY." }
if ([string]$ready.version -ne "0.14.0") { throw "Live API version is not 0.14.0." }
if ([string]$ready.database -ne "reachable") { throw "Database is not reachable." }
if ($ready.async_jobs.reachable -ne $true -or [int]$ready.async_jobs.workers -lt 1) { throw "Redis/worker readiness failed." }

$apiCid = ([string](& docker.exe compose --env-file $envFile -f $compose ps -q api)).Trim()
if ([string]::IsNullOrWhiteSpace($apiCid)) { throw "API container missing." }
$currentRaw = & docker.exe exec $apiCid alembic current
$current = [string]::Join("`n", [string[]]@($currentRaw)).Trim()
if ($current -notmatch "b7f1c2d30001") { throw "Batch-7 Alembic head is not active: $current" }

& docker.exe exec $apiCid python -m scripts.verify_batch7_release --containerized
if ($LASTEXITCODE -ne 0) { throw "Containerized Batch-7 release contract failed." }

$metricsRaw = & docker.exe exec $apiCid python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:10000/internal/metrics', timeout=10).read().decode())"
if ($LASTEXITCODE -ne 0) { throw "Internal metrics endpoint failed." }
$metrics = [string]::Join("`n", [string[]]@($metricsRaw))
if ($metrics -notmatch "threatlens_process_uptime_seconds" -or $metrics -notmatch "threatlens_ai_workers") { throw "Required application metrics missing." }

if ($RequireObservability) {
    $prom = Invoke-WebRequest -Uri "http://127.0.0.1:9090/-/ready" -UseBasicParsing -TimeoutSec 20
    if ([int]$prom.StatusCode -ne 200) { throw "Prometheus is not ready." }
    $graf = Invoke-WebRequest -Uri "http://127.0.0.1:3000/api/health" -UseBasicParsing -TimeoutSec 20
    if ([int]$graf.StatusCode -ne 200) { throw "Grafana is not ready." }
}

Write-Host "THREATLENS BATCH 7 LIVE FOUNDATION: PASS" -ForegroundColor Green
Write-Host "NEXT: measured load, backup/restore smoke, outage drills and browser observability UAT." -ForegroundColor Cyan
