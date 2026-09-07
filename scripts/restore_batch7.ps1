param(
    [Parameter(Mandatory=$true)][string]$BackupDirectory,
    [Parameter(Mandatory=$true)][string]$TargetDatabase,
    [switch]$AllowPrimaryDatabaseRestore
)

$ErrorActionPreference = "Stop"
if ($TargetDatabase -eq "threatlens" -and -not $AllowPrimaryDatabaseRestore) {
    throw "Primary database restore is blocked by default. Re-run with -AllowPrimaryDatabaseRestore only during an approved recovery window."
}
if ($TargetDatabase -notmatch '^[A-Za-z0-9_]+$') { throw "TargetDatabase contains unsupported characters." }

$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
$manifestPath = Join-Path $BackupDirectory "manifest.json"
$dumpPath = Join-Path $BackupDirectory "threatlens.dump"
if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $dumpPath)) { throw "Backup is incomplete." }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$actual = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne [string]$manifest.dump_sha256) { throw "Backup dump SHA-256 mismatch." }

$cidRaw = & docker.exe compose --env-file $envFile -f $compose ps -q postgres
if ($LASTEXITCODE -ne 0) { throw "Could not locate PostgreSQL container." }
$cid = ([string]$cidRaw).Trim()
if ([string]::IsNullOrWhiteSpace($cid)) { throw "PostgreSQL container is not running." }

$inside = "/tmp/threatlens-approved-restore.dump"
try {
    & docker.exe cp $dumpPath ($cid + ":" + $inside)
    if ($LASTEXITCODE -ne 0) { throw "Could not copy dump into container." }

    if ($TargetDatabase -eq "threatlens") {
        Write-Host "PRIMARY DATABASE RESTORE AUTHORIZED. Stop API/worker before continuing in production." -ForegroundColor Red
    }
    & docker.exe exec $cid dropdb -U threatlens --if-exists $TargetDatabase
    if ($LASTEXITCODE -ne 0) { throw "Could not drop target database." }
    & docker.exe exec $cid createdb -U threatlens $TargetDatabase
    if ($LASTEXITCODE -ne 0) { throw "Could not create target database." }
    & docker.exe exec $cid pg_restore -U threatlens -d $TargetDatabase --no-owner --no-privileges $inside
    if ($LASTEXITCODE -ne 0) { throw "Approved restore failed." }
    Write-Host "ThreatLens restore completed: $TargetDatabase" -ForegroundColor Green
}
finally {
    & docker.exe exec $cid rm -f $inside 2>$null | Out-Null
}
