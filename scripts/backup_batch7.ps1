param(
    [string]$DestinationRoot = "D:\ThreatLensAI_Runtime\backups\batch7"
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
if (-not (Test-Path -LiteralPath $envFile)) { throw ".env.batch7.local is missing." }

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

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$destination = Join-Path $DestinationRoot $stamp
New-Item -ItemType Directory -Path $destination -Force | Out-Null

$postgres = Invoke-Docker -Arguments @(
    "compose","--env-file",$envFile,"-f",$compose,"ps","-q","postgres"
) -Label "Locate Batch-7 PostgreSQL container"
$cid = ([string]$postgres.Text).Trim()
if ([string]::IsNullOrWhiteSpace($cid)) { throw "Batch-7 PostgreSQL container is not running." }

$insideDump = "/tmp/threatlens-batch7-$stamp.dump"
$insideGlobals = "/tmp/threatlens-batch7-$stamp-globals.sql"

$null = Invoke-Docker -Arguments @(
    "exec",$cid,"pg_dump","-U","threatlens","-d","threatlens","-Fc","-f",$insideDump
) -Label "pg_dump"
$null = Invoke-Docker -Arguments @(
    "exec",$cid,"pg_dumpall","-U","threatlens","--globals-only","-f",$insideGlobals
) -Label "pg_dumpall globals"

$dumpPath = Join-Path $destination "threatlens.dump"
$globalsPath = Join-Path $destination "globals.sql"

$null = Invoke-Docker -Arguments @("cp",($cid + ":" + $insideDump),$dumpPath) -Label "Copy database dump"
$null = Invoke-Docker -Arguments @("cp",($cid + ":" + $insideGlobals),$globalsPath) -Label "Copy globals dump"

$cleanup = Invoke-Docker -Arguments @(
    "exec",$cid,"rm","-f",$insideDump,$insideGlobals
) -Label "Clean temporary backup files" -AllowFailure
if ($cleanup.ExitCode -ne 0) {
    Write-Warning "Temporary backup files could not be removed from the PostgreSQL container."
}

$dumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
$globalsHash = (Get-FileHash -LiteralPath $globalsPath -Algorithm SHA256).Hash.ToLowerInvariant()

$head = "unknown"
$api = Invoke-Docker -Arguments @(
    "compose","--env-file",$envFile,"-f",$compose,"ps","-q","api"
) -Label "Locate Batch-7 API container" -AllowFailure

if ($api.ExitCode -eq 0) {
    $apiCid = ([string]$api.Text).Trim()
    if (-not [string]::IsNullOrWhiteSpace($apiCid)) {
        $alembic = Invoke-Docker -Arguments @(
            "exec",$apiCid,"alembic","current"
        ) -Label "Read Alembic head" -AllowFailure

        if ($alembic.ExitCode -eq 0) {
            $head = ([string]$alembic.Text).Trim()
        }
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

$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (
    Join-Path $destination "manifest.json"
) -Encoding UTF8

Write-Host "THREATLENS BATCH 7 BACKUP: PASS" -ForegroundColor Green
Write-Host "Backup: $destination" -ForegroundColor Cyan
Write-Host "Dump SHA256: $dumpHash" -ForegroundColor Cyan