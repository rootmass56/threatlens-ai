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

function Invoke-Docker {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [string]$Label = "docker.exe",
        [switch]$AllowFailure
    )

    $stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        "threatlens-docker-stderr-" + [guid]::NewGuid().ToString("N") + ".txt"
    )
    $savedPreference = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Continue"
        $stdout = @(& docker.exe @Arguments 2> $stderrPath)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }

    $stderr = @()
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        $stderr = @(Get-Content -LiteralPath $stderrPath | ForEach-Object { [string]$_ })
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    if (($exitCode -ne 0) -and (-not $AllowFailure)) {
        $detail = [string]::Join("`n",[string[]]$stderr).Trim()
        throw ($Label + " failed with exit code " + $exitCode + ".`n" + $detail)
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        StdOut = @($stdout | ForEach-Object { [string]$_ })
        StdErr = $stderr
        Text = [string]::Join("`n",[string[]]@($stdout)).Trim()
    }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$actual = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne [string]$manifest.dump_sha256) { throw "Backup dump SHA-256 mismatch." }

$postgres = Invoke-Docker -Arguments @(
    "compose","--env-file",$envFile,"-f",$compose,"ps","-q","postgres"
) -Label "Locate PostgreSQL container"
$cid = ([string]$postgres.Text).Trim()
if ([string]::IsNullOrWhiteSpace($cid)) { throw "PostgreSQL container is not running." }

$suffix = Get-Date -Format "yyyyMMddHHmmss"
$db = "threatlens_restore_smoke_$suffix"
$inside = "/tmp/threatlens-restore-$suffix.dump"

try {
    $null = Invoke-Docker -Arguments @(
        "cp",$dumpPath,($cid + ":" + $inside)
    ) -Label "Copy backup into PostgreSQL container"

    $null = Invoke-Docker -Arguments @(
        "exec",$cid,"createdb","-U","threatlens",$db
    ) -Label "Create isolated restore-smoke database"

    $null = Invoke-Docker -Arguments @(
        "exec",$cid,"pg_restore","-U","threatlens","-d",$db,
        "--no-owner","--no-privileges",$inside
    ) -Label "Restore isolated smoke database"

    $tablesResult = Invoke-Docker -Arguments @(
        "exec",$cid,"psql","-U","threatlens","-d",$db,"-Atc",
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
    ) -Label "Query restored table count"
    $tables = [int](([string]$tablesResult.Text).Trim())
    if ($tables -lt 20) { throw "Restored database has unexpectedly few public tables: $tables" }

    $pgvectorResult = Invoke-Docker -Arguments @(
        "exec",$cid,"psql","-U","threatlens","-d",$db,"-Atc",
        "SELECT count(*) FROM pg_extension WHERE extname='vector';"
    ) -Label "Verify pgvector after restore"
    if ([int](([string]$pgvectorResult.Text).Trim()) -ne 1) {
        throw "pgvector extension missing after restore."
    }

    Write-Host "THREATLENS BATCH 7 BACKUP / RESTORE SMOKE: PASS" -ForegroundColor Green
    Write-Host "Isolated restored tables: $tables" -ForegroundColor Green
}
finally {
    $drop = Invoke-Docker -Arguments @(
        "exec",$cid,"dropdb","-U","threatlens","--if-exists",$db
    ) -Label "Drop isolated restore-smoke database" -AllowFailure

    $remove = Invoke-Docker -Arguments @(
        "exec",$cid,"rm","-f",$inside
    ) -Label "Remove isolated restore dump" -AllowFailure

    if (($drop.ExitCode -ne 0) -or ($remove.ExitCode -ne 0)) {
        Write-Warning "Restore-smoke cleanup reported a native-command failure."
    }
}