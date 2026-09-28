param(
    [string]$Batch6Project = "D:\projects\ThreatLensAI_v0.13_BATCH6_ADVANCED_SOC_RC_FULL",
    [switch]$StartObservability
)

$ErrorActionPreference = "Stop"
$batch7Project = Split-Path -Parent $PSScriptRoot
$batch6Env = Join-Path $Batch6Project ".env.batch6.local"
$batch6Compose = Join-Path $Batch6Project "deploy/compose/legacy/batch6.yml"
$batch7Env = Join-Path $batch7Project ".env.batch7.local"
$batch7Compose = Join-Path $batch7Project "compose.yaml"

foreach ($path in @($batch6Env,$batch6Compose,$batch7Compose)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required migration input missing: $path" }
}
if (-not (Test-Path -LiteralPath $batch7Env)) {
    & (Join-Path $PSScriptRoot "bootstrap_batch7_env.ps1")
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$migrationDir = "D:\ThreatLensAI_Runtime\migrations\batch6-to-batch7-$stamp"
New-Item -ItemType Directory -Path $migrationDir -Force | Out-Null
$dumpPath = Join-Path $migrationDir "batch6-v0130.dump"

Write-Host "[1/6] Verifying frozen Batch-6 PostgreSQL source..." -ForegroundColor Yellow
& docker.exe compose --env-file $batch6Env -f $batch6Compose up -d postgres
if ($LASTEXITCODE -ne 0) { throw "Could not start Batch-6 PostgreSQL." }
$sourceCid = ([string](& docker.exe compose --env-file $batch6Env -f $batch6Compose ps -q postgres)).Trim()
if ([string]::IsNullOrWhiteSpace($sourceCid)) { throw "Batch-6 PostgreSQL container missing." }

$insideSource = "/tmp/batch6-v0130-migration.dump"
& docker.exe exec $sourceCid pg_dump -U threatlens -d threatlens -Fc -f $insideSource
if ($LASTEXITCODE -ne 0) { throw "Batch-6 pg_dump failed." }
& docker.exe cp ($sourceCid + ":" + $insideSource) $dumpPath
if ($LASTEXITCODE -ne 0) { throw "Could not copy Batch-6 dump." }
& docker.exe exec $sourceCid rm -f $insideSource | Out-Null
$hash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "[OK] Frozen source database captured. SHA256=$hash" -ForegroundColor Green

Write-Host "[2/6] Starting isolated Batch-7 PostgreSQL + Redis volumes..." -ForegroundColor Yellow
& docker.exe compose --env-file $batch7Env -f $batch7Compose up -d postgres redis
if ($LASTEXITCODE -ne 0) { throw "Could not start Batch-7 data services." }
Start-Sleep -Seconds 5
$targetCid = ([string](& docker.exe compose --env-file $batch7Env -f $batch7Compose ps -q postgres)).Trim()
if ([string]::IsNullOrWhiteSpace($targetCid)) { throw "Batch-7 PostgreSQL container missing." }

$existingRaw = & docker.exe exec $targetCid psql -U threatlens -d threatlens -Atc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
if ($LASTEXITCODE -ne 0) { throw "Could not inspect Batch-7 target database." }
$existing = [int](([string]$existingRaw).Trim())
if ($existing -gt 0) {
    throw "Batch-7 target database already contains $existing public tables. Migration refuses to overwrite it. Use the existing Batch-7 database or remove only the Batch-7 volumes after taking a backup."
}

Write-Host "[3/6] Restoring frozen Batch-6 database into isolated Batch-7 volume..." -ForegroundColor Yellow
$insideTarget = "/tmp/batch6-v0130-migration.dump"
& docker.exe cp $dumpPath ($targetCid + ":" + $insideTarget)
if ($LASTEXITCODE -ne 0) { throw "Could not copy migration dump into Batch-7 PostgreSQL." }
& docker.exe exec $targetCid pg_restore -U threatlens -d threatlens --no-owner --no-privileges $insideTarget
if ($LASTEXITCODE -ne 0) { throw "Batch-6 -> Batch-7 pg_restore failed." }
& docker.exe exec $targetCid rm -f $insideTarget | Out-Null
Write-Host "[OK] Frozen operational data restored into Batch-7 PostgreSQL." -ForegroundColor Green

Write-Host "[4/6] Starting Batch-7 API/worker/frontend and applying Batch-7 migration..." -ForegroundColor Yellow
$args = @("compose")
if ($StartObservability) { $args += @("--profile","observability") }
$args += @("--env-file",$batch7Env,"-f",$batch7Compose,"up","--build","-d","api","worker","frontend")
if ($StartObservability) { $args += @("prometheus","grafana","postgres_exporter","redis_exporter") }
& docker.exe @args
if ($LASTEXITCODE -ne 0) { throw "Batch-7 application startup failed." }

Write-Host "[5/6] Waiting for Batch-7 readiness..." -ForegroundColor Yellow
$deadline = (Get-Date).AddMinutes(5)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/health/ready" -TimeoutSec 10 -ErrorAction Stop
        if ([string]$r.status -eq "ready" -and [string]$r.version -eq "0.14.0") { $ready = $true; break }
    } catch {}
    Start-Sleep -Seconds 3
}
if (-not $ready) { throw "Batch-7 API did not become READY after migration." }
Write-Host "[OK] Batch-7 API READY." -ForegroundColor Green

Write-Host "[6/6] Verifying Alembic Batch-7 head + preserved operational data..." -ForegroundColor Yellow
$apiCid = ([string](& docker.exe compose --env-file $batch7Env -f $batch7Compose ps -q api)).Trim()
$currentRaw = & docker.exe exec $apiCid alembic current
$current = [string]::Join("`n",[string[]]@($currentRaw)).Trim()
if ($current -notmatch "b7f1c2d30001") { throw "Batch-7 migration head not observed. Current: $current" }
$countRaw = & docker.exe exec $targetCid psql -U threatlens -d threatlens -Atc "SELECT count(*) FROM analysis_sessions;"
if ($LASTEXITCODE -ne 0) { throw "Could not verify migrated analyses." }
Write-Host "THREATLENS BATCH 6 -> BATCH 7 DATA MIGRATION: PASS" -ForegroundColor Green
Write-Host "Preserved analysis sessions: $(([string]$countRaw).Trim())" -ForegroundColor Green
Write-Host "Migration evidence: $migrationDir" -ForegroundColor Cyan
