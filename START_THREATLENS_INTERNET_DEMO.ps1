param(
    [switch]$NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeRoot = "D:\ThreatLensAI_Runtime"
$StateRoot = Join-Path $RuntimeRoot "phase9_internet_demo"
$StateFile = Join-Path $StateRoot "active-tunnel.json"

$ProjectName = "threatlens-batch7"
$RequiredBranch = "phase9/secure-temporary-internet-demo"
$RequiredAncestor = "6b36688ddc33a98d6cd47eda8e61a9fdda965790"

$ComposeBase = Join-Path $Project "compose.batch7.yml"
$ComposeInternet = Join-Path $Project "compose.phase9.internet.yml"
$EnvFile = Join-Path $Project ".env.batch7.local"
$HealthChecker = Join-Path $Project "CHECK_THREATLENS.ps1"
$Verifier = Join-Path $Project "scripts\verify_internet_demo.py"

$Origin = "http://127.0.0.1:8080"
$TempRoot = Join-Path $env:TEMP ("threatlens-phase9-start-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
$script:NativeCounter = 0
$tunnelProcess = $null

function Fail {
    param([Parameter(Mandatory=$true)][string]$Message)
    throw $Message
}

function Invoke-Native {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$Label,
        [switch]$EchoStdout,
        [switch]$AllowFailure
    )

    $script:NativeCounter++
    $stdoutPath = Join-Path $TempRoot ("{0:D3}.stdout.txt" -f $script:NativeCounter)
    $stderrPath = Join-Path $TempRoot ("{0:D3}.stderr.txt" -f $script:NativeCounter)

    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $stdoutText = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllText($stdoutPath) } else { "" }
    $stderrText = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllText($stderrPath) } else { "" }

    if ($EchoStdout -and -not [string]::IsNullOrWhiteSpace($stdoutText)) { Write-Host $stdoutText.TrimEnd() }
    if (-not [string]::IsNullOrWhiteSpace($stderrText)) { Write-Host $stderrText.TrimEnd() -ForegroundColor DarkGray }

    if (-not $AllowFailure -and [int]$process.ExitCode -ne 0) {
        Fail -Message ("{0} failed with native exit code {1}." -f $Label,$process.ExitCode)
    }

    [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        Stdout = $stdoutText
        Stderr = $stderrText
    }
}

function Invoke-FullHealth {
    return Invoke-Native `
        -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy","Bypass",
            "-File",$HealthChecker,
            "-RequireObservability",
            "-RequireAI"
        ) `
        -Label "full-health" `
        -EchoStdout
}

function Wait-LocalReady {
    $deadline = (Get-Date).AddMinutes(6)

    do {
        try {
            $front = Invoke-WebRequest -UseBasicParsing -Uri "$Origin/" -TimeoutSec 8
            $ready = Invoke-RestMethod -Uri "$Origin/api/v1/health/ready" -TimeoutSec 8

            if (
                [int]$front.StatusCode -eq 200 -and
                [string]$ready.status -eq "ready"
            ) {
                return
            }
        }
        catch {}

        Start-Sleep -Seconds 4
    }
    while ((Get-Date) -lt $deadline)

    Fail -Message "Phase9 local frontend/API did not become ready within six minutes."
}

function Invoke-PublicCheck {
    param([Parameter(Mandatory=$true)][string]$PublicUrl)

    $deadline = (Get-Date).AddMinutes(2)

    do {
        try {
            $root = Invoke-WebRequest -UseBasicParsing -Uri ($PublicUrl.TrimEnd("/") + "/") -TimeoutSec 15
            $live = Invoke-RestMethod -Uri ($PublicUrl.TrimEnd("/") + "/api/v1/health/live") -TimeoutSec 15

            if ([int]$root.StatusCode -eq 200 -and [string]$live.status -eq "ok") {
                return
            }
        }
        catch {}

        Start-Sleep -Seconds 4
    }
    while ((Get-Date) -lt $deadline)

    Fail -Message "The Quick Tunnel URL did not become a healthy ThreatLens HTTPS endpoint."
}

try {
    Write-Host ""
    Write-Host ("=" * 104) -ForegroundColor Cyan
    Write-Host "THREATLENS AI - SECURE TEMPORARY INTERNET DEMO" -ForegroundColor Cyan
    Write-Host ("=" * 104) -ForegroundColor Cyan

    foreach ($required in @($ComposeBase,$ComposeInternet,$EnvFile,$HealthChecker,$Verifier)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            Fail -Message ("Required Phase9 file missing: {0}" -f $required)
        }
    }

    Write-Host "[1/6] Validate accepted Phase9 source lineage and local safety" -ForegroundColor Yellow

    $branchRun = Invoke-Native -FilePath "git.exe" -ArgumentList @("-C",$Project,"branch","--show-current") -Label "branch"
    $branch = ([string]$branchRun.Stdout).Trim()

    if ($branch -ne $RequiredBranch) {
        Fail -Message ("Internet Demo requires branch {0}; found {1}." -f $RequiredBranch,$branch)
    }

    $ancestorRun = Invoke-Native `
        -FilePath "git.exe" `
        -ArgumentList @("-C",$Project,"merge-base","--is-ancestor",$RequiredAncestor,"HEAD") `
        -Label "lineage" `
        -AllowFailure

    if ([int]$ancestorRun.ExitCode -ne 0) {
        Fail -Message "Current Phase9 branch is not descended from the frozen Phase6 source."
    }

    $statusRun = Invoke-Native `
        -FilePath "git.exe" `
        -ArgumentList @("-C",$Project,"status","--porcelain=v1","--untracked-files=all") `
        -Label "worktree"

    if (-not [string]::IsNullOrWhiteSpace([string]$statusRun.Stdout)) {
        Fail -Message "Internet Demo requires a clean Phase9 worktree."
    }

    if (Test-Path -LiteralPath $StateFile -PathType Leaf) {
        Fail -Message ("An internet-demo state file already exists. Run STOP_THREATLENS_INTERNET_DEMO.ps1 first: {0}" -f $StateFile)
    }

    $configYaml = Join-Path $env:USERPROFILE ".cloudflared\config.yaml"
    $configYml = Join-Path $env:USERPROFILE ".cloudflared\config.yml"

    if (
        (Test-Path -LiteralPath $configYaml -PathType Leaf) -or
        (Test-Path -LiteralPath $configYml -PathType Leaf)
    ) {
        Fail -Message "A Cloudflare Tunnel config file exists under ~/.cloudflared. Quick Tunnel mode can conflict with it. This launcher will not read, rename, overwrite, or delete it."
    }

    $cloudflared = Get-Command "cloudflared.exe" -ErrorAction SilentlyContinue
    if ($null -eq $cloudflared) {
        Fail -Message "cloudflared is not installed or not on PATH. Install the official client first: winget install --id Cloudflare.cloudflared -e"
    }

    Write-Host "[OK] Phase9 lineage/worktree/config safety PASS." -ForegroundColor Green

    Write-Host ""
    Write-Host "[2/6] Apply Phase9 Compose profile non-destructively" -ForegroundColor Yellow

    $null = Invoke-Native `
        -FilePath "docker.exe" `
        -ArgumentList @(
            "compose",
            "--project-directory",$Project,
            "-p",$ProjectName,
            "--profile","observability",
            "--env-file",$EnvFile,
            "-f",$ComposeBase,
            "-f",$ComposeInternet,
            "up","-d","--build"
        ) `
        -Label "compose-phase9-up" `
        -EchoStdout

    Wait-LocalReady
    $null = Invoke-FullHealth

    $front = Invoke-WebRequest -UseBasicParsing -Uri "$Origin/" -TimeoutSec 10
    $frontHsts = [string]$front.Headers["Strict-Transport-Security"]
    if (-not $frontHsts.ToLowerInvariant().Contains("max-age=")) {
        Fail -Message "Phase9 frontend HSTS header is missing."
    }

    Write-Host "[OK] Phase9 local runtime/observability/RAG + frontend security profile PASS." -ForegroundColor Green

    Write-Host ""
    Write-Host "[3/6] Start one temporary Cloudflare Quick Tunnel" -ForegroundColor Yellow

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $stdoutPath = Join-Path $StateRoot ("cloudflared-" + $stamp + ".stdout.log")
    $stderrPath = Join-Path $StateRoot ("cloudflared-" + $stamp + ".stderr.log")

    $tunnelProcess = Start-Process `
        -FilePath $cloudflared.Source `
        -ArgumentList @("--no-autoupdate","tunnel","--url",$Origin) `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $publicUrl = ""

    for ($attempt = 1; $attempt -le 45; $attempt++) {
        Start-Sleep -Seconds 2

        if ($tunnelProcess.HasExited) {
            $details = ""
            if (Test-Path -LiteralPath $stderrPath) { $details = [IO.File]::ReadAllText($stderrPath) }
            Fail -Message ("cloudflared exited before publishing a Quick Tunnel URL. {0}" -f $details.Trim())
        }

        $combined = ""
        if (Test-Path -LiteralPath $stdoutPath) { $combined += [IO.File]::ReadAllText($stdoutPath) }
        if (Test-Path -LiteralPath $stderrPath) { $combined += "`n" + [IO.File]::ReadAllText($stderrPath) }

        $match = [regex]::Match($combined, 'https://[a-z0-9-]+\.trycloudflare\.com', [Text.RegularExpressions.RegexOptions]::IgnoreCase)

        if ($match.Success) {
            $publicUrl = $match.Value.TrimEnd("/")
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($publicUrl)) {
        Fail -Message "cloudflared did not publish a trycloudflare.com URL within 90 seconds."
    }

    Write-Host ("[OK] Quick Tunnel published: {0}" -f $publicUrl) -ForegroundColor Green

    Write-Host ""
    Write-Host "[4/6] Record exact tunnel process for controlled shutdown" -ForegroundColor Yellow

    $state = [ordered]@{
        status = "ACTIVE"
        public_url = $publicUrl
        local_origin = $Origin
        process_id = [int]$tunnelProcess.Id
        executable = [string]$cloudflared.Source
        stdout_log = $stdoutPath
        stderr_log = $stderrPath
        started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    }

    [IO.File]::WriteAllText(
        $StateFile,
        ($state | ConvertTo-Json -Depth 20),
        (New-Object Text.UTF8Encoding($false))
    )

    Write-Host "[OK] Exact tunnel PID/state recorded; no credential/token stored." -ForegroundColor Green

    Write-Host ""
    Write-Host "[5/6] Verify remote HTTPS frontend, same-origin API, auth boundary, and non-exposure" -ForegroundColor Yellow

    Invoke-PublicCheck -PublicUrl $publicUrl

    $verifyRun = Invoke-Native `
        -FilePath "python.exe" `
        -ArgumentList @($Verifier,"--url",$publicUrl) `
        -Label "public-verifier" `
        -EchoStdout

    if ([int]$verifyRun.ExitCode -ne 0) {
        Fail -Message "Phase9 public verification failed."
    }

    Write-Host "[OK] Remote internet-demo boundary PASS." -ForegroundColor Green

    Write-Host ""
    Write-Host "[6/6] Internet demo ready" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("TEMPORARY URL : {0}" -f $publicUrl) -ForegroundColor Cyan
    Write-Host "Authentication: REQUIRED. Use your existing authorized ThreatLens account." -ForegroundColor Yellow
    Write-Host "Do not share credentials or leave this tunnel running unattended." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "When finished, run:" -ForegroundColor Cyan
    Write-Host "  .\STOP_THREATLENS_INTERNET_DEMO.ps1"
    Write-Host ""

    if (-not $NoBrowser) {
        Start-Process $publicUrl | Out-Null
    }

    Write-Host "THREATLENS SECURE TEMPORARY INTERNET DEMO: READY" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host ""
    Write-Host "THREATLENS SECURE TEMPORARY INTERNET DEMO: NOT READY" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    if ($null -ne $tunnelProcess) {
        try {
            if (-not $tunnelProcess.HasExited) {
                Stop-Process -Id $tunnelProcess.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }

    try {
        if (Test-Path -LiteralPath $StateFile) {
            Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    exit 1
}
finally {
    try {
        if (Test-Path -LiteralPath $TempRoot) {
            Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}
