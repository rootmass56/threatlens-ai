param(
    [Parameter(Mandatory=$true)][string]$BackupDirectory,
    [Parameter(Mandatory=$true)][string]$TargetDatabase,
    [switch]$AllowPrimaryDatabaseRestore
)

$ErrorActionPreference = "Stop"

if ($TargetDatabase -eq "threatlens" -and -not $AllowPrimaryDatabaseRestore) {
    throw "Primary database restore is blocked by default. Re-run with -AllowPrimaryDatabaseRestore only during an approved recovery window."
}
if ($TargetDatabase -notmatch '^[A-Za-z0-9_]+$') {
    throw "TargetDatabase contains unsupported characters."
}

$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"
$manifestPath = Join-Path $BackupDirectory "manifest.json"
$dumpPath = Join-Path $BackupDirectory "threatlens.dump"

if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $dumpPath)) {
    throw "Backup is incomplete."
}

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

$inside = "/tmp/threatlens-approved-restore.dump"

try {
    $null = Invoke-Docker -Arguments @(
        "cp",$dumpPath,($cid + ":" + $inside)
    ) -Label "Copy approved restore dump into container"

    if ($TargetDatabase -eq "threatlens") {
        Write-Host "PRIMARY DATABASE RESTORE AUTHORIZED. Stop API/worker before continuing in production." -ForegroundColor Red
    }

    $null = Invoke-Docker -Arguments @(
        "exec",$cid,"dropdb","-U","threatlens","--if-exists",$TargetDatabase
    ) -Label "Drop approved restore target"

    $null = Invoke-Docker -Arguments @(
        "exec",$cid,"createdb","-U","threatlens",$TargetDatabase
    ) -Label "Create approved restore target"

    $null = Invoke-Docker -Arguments @(
        "exec",$cid,"pg_restore","-U","threatlens","-d",$TargetDatabase,
        "--no-owner","--no-privileges",$inside
    ) -Label "Approved database restore"

    Write-Host "ThreatLens restore completed: $TargetDatabase" -ForegroundColor Green
}
finally {
    $cleanup = Invoke-Docker -Arguments @(
        "exec",$cid,"rm","-f",$inside
    ) -Label "Remove approved restore dump" -AllowFailure

    if ($cleanup.ExitCode -ne 0) {
        Write-Warning "Approved restore cleanup reported a native-command failure."
    }
}