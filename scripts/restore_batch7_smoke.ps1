param(
    [Parameter(Mandatory=$true)][string]$BackupDirectory
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
$manifestPath = Join-Path $BackupDirectory "manifest.json"
$dumpPath = Join-Path $BackupDirectory "threatlens.dump"
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Backup manifest missing." }
if (-not (Test-Path -LiteralPath $dumpPath)) { throw "Backup dump missing." }

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$actual = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne [string]$manifest.dump_sha256) { throw "Backup dump SHA-256 mismatch." }

$cidRaw = & docker.exe compose --env-file $envFile -f $compose ps -q postgres
if ($LASTEXITCODE -ne 0) { throw "Could not locate PostgreSQL container." }
$cid = [string]$cidRaw
$cid = $cid.Trim()
if ([string]::IsNullOrWhiteSpace($cid)) { throw "PostgreSQL container is not running." }

$suffix = Get-Date -Format "yyyyMMddHHmmss"
$db = "threatlens_restore_smoke_$suffix"
$inside = "/tmp/threatlens-restore-$suffix.dump"

try {
    & docker.exe cp $dumpPath ($cid + ":" + $inside)
    if ($LASTEXITCODE -ne 0) { throw "Could not copy backup into PostgreSQL container." }
    & docker.exe exec $cid createdb -U threatlens $db
    if ($LASTEXITCODE -ne 0) { throw "Could not create isolated restore-smoke database." }
    & docker.exe exec $cid pg_restore -U threatlens -d $db --no-owner --no-privileges $inside
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed in isolated smoke database." }

    $tablesRaw = & docker.exe exec $cid psql -U threatlens -d $db -Atc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
    if ($LASTEXITCODE -ne 0) { throw "Could not query restored database." }
    $tables = [int](([string]$tablesRaw).Trim())
    if ($tables -lt 20) { throw "Restored database has unexpectedly few public tables: $tables" }

    $pgvectorRaw = & docker.exe exec $cid psql -U threatlens -d $db -Atc "SELECT count(*) FROM pg_extension WHERE extname='vector';"
    if ($LASTEXITCODE -ne 0) { throw "Could not verify pgvector in restored database." }
    if ([int](([string]$pgvectorRaw).Trim()) -ne 1) { throw "pgvector extension missing after restore." }

    Write-Host "THREATLENS BATCH 7 BACKUP / RESTORE SMOKE: PASS" -ForegroundColor Green
    Write-Host "Isolated restored tables: $tables" -ForegroundColor Green
}
finally {
    & docker.exe exec $cid dropdb -U threatlens --if-exists $db 2>$null | Out-Null
    & docker.exe exec $cid rm -f $inside 2>$null | Out-Null
}
