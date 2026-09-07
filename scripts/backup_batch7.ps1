param(
    [string]$DestinationRoot = "D:\ThreatLensAI_Runtime\backups\batch7"
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
if (-not (Test-Path -LiteralPath $envFile)) { throw ".env.batch7.local is missing." }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$destination = Join-Path $DestinationRoot $stamp
New-Item -ItemType Directory -Path $destination -Force | Out-Null

$cidRaw = & docker.exe compose --env-file $envFile -f $compose ps -q postgres
if ($LASTEXITCODE -ne 0) { throw "Could not locate Batch-7 PostgreSQL container." }
$cid = [string]$cidRaw
$cid = $cid.Trim()
if ([string]::IsNullOrWhiteSpace($cid)) { throw "Batch-7 PostgreSQL container is not running." }

$insideDump = "/tmp/threatlens-batch7-$stamp.dump"
$insideGlobals = "/tmp/threatlens-batch7-$stamp-globals.sql"

& docker.exe exec $cid pg_dump -U threatlens -d threatlens -Fc -f $insideDump
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed." }
& docker.exe exec $cid pg_dumpall -U threatlens --globals-only -f $insideGlobals
if ($LASTEXITCODE -ne 0) { throw "pg_dumpall globals failed." }

$dumpPath = Join-Path $destination "threatlens.dump"
$globalsPath = Join-Path $destination "globals.sql"
& docker.exe cp ($cid + ":" + $insideDump) $dumpPath
if ($LASTEXITCODE -ne 0) { throw "Could not copy database dump from container." }
& docker.exe cp ($cid + ":" + $insideGlobals) $globalsPath
if ($LASTEXITCODE -ne 0) { throw "Could not copy globals dump from container." }
& docker.exe exec $cid rm -f $insideDump $insideGlobals | Out-Null

$dumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
$globalsHash = (Get-FileHash -LiteralPath $globalsPath -Algorithm SHA256).Hash.ToLowerInvariant()

$head = "unknown"
$apiCidRaw = & docker.exe compose --env-file $envFile -f $compose ps -q api
if ($LASTEXITCODE -eq 0) {
    $apiCid = [string]$apiCidRaw
    $apiCid = $apiCid.Trim()
    if (-not [string]::IsNullOrWhiteSpace($apiCid)) {
        $headRaw = & docker.exe exec $apiCid alembic current 2>$null
        if ($LASTEXITCODE -eq 0) { $head = ([string]::Join("`n", [string[]]@($headRaw))).Trim() }
    }
}

$manifest = [ordered]@{
    project = "ThreatLens AI"
    version = "0.14.0"
    batch = 7
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    database = "threatlens"
    format = "pg_dump custom"
    alembic_current = $head
    dump_file = "threatlens.dump"
    dump_sha256 = $dumpHash
    globals_file = "globals.sql"
    globals_sha256 = $globalsHash
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination "manifest.json") -Encoding UTF8

Write-Host "THREATLENS BATCH 7 BACKUP: PASS" -ForegroundColor Green
Write-Host "Backup: $destination" -ForegroundColor Cyan
Write-Host "Dump SHA256: $dumpHash" -ForegroundColor Cyan
