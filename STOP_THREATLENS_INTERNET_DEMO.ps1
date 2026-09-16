param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeRoot = "D:\ThreatLensAI_Runtime"
$StateRoot = Join-Path $RuntimeRoot "phase9_internet_demo"
$StateFile = Join-Path $StateRoot "active-tunnel.json"
$HealthChecker = Join-Path $Project "CHECK_THREATLENS.ps1"

function Fail {
    param([Parameter(Mandatory=$true)][string]$Message)
    throw $Message
}

try {
    Write-Host ""
    Write-Host ("=" * 100) -ForegroundColor Cyan
    Write-Host "THREATLENS AI - STOP SECURE TEMPORARY INTERNET DEMO" -ForegroundColor Cyan
    Write-Host ("=" * 100) -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $StateFile -PathType Leaf)) {
        Fail -Message ("No active Phase9 tunnel state file exists: {0}" -f $StateFile)
    }

    $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    $processId = [int]$state.process_id
    $publicUrl = [string]$state.public_url

    Write-Host "[1/4] Validate exact recorded cloudflared process" -ForegroundColor Yellow

    $processInfo = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $processId) -ErrorAction SilentlyContinue

    if ($null -eq $processInfo) {
        Write-Host "[INFO] Recorded tunnel process is already stopped." -ForegroundColor Cyan
    }
    else {
        $name = [string]$processInfo.Name
        $commandLine = [string]$processInfo.CommandLine

        if (-not $name.ToLowerInvariant().Contains("cloudflared")) {
            Fail -Message ("PID {0} is no longer cloudflared; refusing to terminate an unrelated process." -f $processId)
        }

        if (
            -not $commandLine.ToLowerInvariant().Contains("tunnel") -or
            -not $commandLine.Contains("127.0.0.1:8080")
        ) {
            Fail -Message ("PID {0} command line does not match the recorded ThreatLens Quick Tunnel; refusing to terminate it." -f $processId)
        }

        Write-Host "[OK] Recorded process identity matches ThreatLens cloudflared tunnel." -ForegroundColor Green

        Write-Host ""
        Write-Host "[2/4] Stop only the exact recorded tunnel process" -ForegroundColor Yellow

        Stop-Process -Id $processId -Force -ErrorAction Stop

        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 500
            $stillThere = Get-Process -Id $processId -ErrorAction SilentlyContinue
        } while ($null -ne $stillThere -and (Get-Date) -lt $deadline)

        if ($null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
            Fail -Message "Recorded cloudflared process did not terminate."
        }

        Write-Host "[OK] Exact cloudflared process stopped." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[3/4] Prove temporary public application is no longer reachable" -ForegroundColor Yellow

    $stillOperational = $false

    for ($attempt = 1; $attempt -le 8; $attempt++) {
        Start-Sleep -Seconds 3
        try {
            $nonce = [Guid]::NewGuid().ToString("N")
            $live = Invoke-RestMethod `
                -Uri ($publicUrl.TrimEnd("/") + "/api/v1/health/live?shutdown=" + $nonce) `
                -TimeoutSec 10

            if ([string]$live.status -eq "ok") {
                $stillOperational = $true
            }
            else {
                $stillOperational = $false
                break
            }
        }
        catch {
            $stillOperational = $false
            break
        }
    }

    if ($stillOperational) {
        Fail -Message "Temporary public ThreatLens API is still reachable after the recorded tunnel process stopped."
    }

    Write-Host "[OK] Temporary public ThreatLens endpoint is no longer operational." -ForegroundColor Green

    Write-Host ""
    Write-Host "[4/4] Verify local ThreatLens remains healthy and clear ephemeral state" -ForegroundColor Yellow

    powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File $HealthChecker `
        -RequireObservability `
        -RequireAI

    if ($LASTEXITCODE -ne 0) {
        Fail -Message "Local ThreatLens health check failed after tunnel shutdown."
    }

    Remove-Item -LiteralPath $StateFile -Force

    Write-Host "[OK] Local ThreatLens remains healthy; ephemeral active-tunnel state removed." -ForegroundColor Green
    Write-Host ""
    Write-Host "THREATLENS TEMPORARY INTERNET DEMO: STOPPED / PUBLIC EXPOSURE REVOKED" -ForegroundColor Green
    Write-Host "Cloudflared log files were preserved under D:\ThreatLensAI_Runtime\phase9_internet_demo for evidence." -ForegroundColor DarkGray
    exit 0
}
catch {
    Write-Host ""
    Write-Host "THREATLENS TEMPORARY INTERNET DEMO STOP: FAIL" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Do NOT kill unrelated processes or delete application data. Inspect the recorded Phase9 state first." -ForegroundColor Yellow
    exit 1
}
