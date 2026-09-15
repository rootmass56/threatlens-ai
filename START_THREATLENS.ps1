param(
    [switch]$CoreOnly,
    [switch]$Build,
    [switch]$RequireAI,
    [int]$TimeoutSeconds = 240,
    [int]$DockerStartupTimeoutSeconds = 180,
    [int]$OllamaStartupTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Project ".env.batch7.local"
$Compose = Join-Path $Project "compose.batch7.yml"
$Check = Join-Path $Project "CHECK_THREATLENS.ps1"
$ProjectName = "threatlens-batch7"

function Test-DockerReady {
    & cmd.exe /d /c "docker info >nul 2>nul"
    return ($LASTEXITCODE -eq 0)
}

function Wait-DockerReady([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        if (Test-DockerReady) { return $true }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Ensure-DockerReady {
    if (Test-DockerReady) {
        Write-Host "[OK] Docker engine ready." -ForegroundColor Green
        return
    }

    Write-Host "[INFO] Docker engine not ready; attempting Docker Desktop startup..." -ForegroundColor Yellow
    # Always materialize an array. In Windows PowerShell 5.1 a pipeline that
    # returns exactly one path becomes a scalar String; under StrictMode that
    # scalar has no .Count property.
    $candidatePaths = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe")
        if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
            Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\Docker Desktop.exe"
        }
    )

    $candidates = @(
        $candidatePaths | Where-Object {
            $_ -and (Test-Path -LiteralPath $_ -PathType Leaf)
        }
    )

    if (@($candidates).Count -eq 0) {
        throw "Docker Desktop is not running and its executable was not found."
    }

    Start-Process -FilePath $candidates[0] | Out-Null
    if (-not (Wait-DockerReady -Seconds $DockerStartupTimeoutSeconds)) {
        throw "Docker engine did not become ready within $DockerStartupTimeoutSeconds seconds."
    }

    Write-Host "[OK] Docker Desktop started and engine is ready." -ForegroundColor Green
}

function Test-OllamaReady {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 4
        return ($response.StatusCode -eq 200)
    }
    catch {
        return $false
    }
}

function Wait-OllamaReady([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        if (Test-OllamaReady) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Ensure-OllamaReady {
    if (Test-OllamaReady) {
        Write-Host "[OK] Ollama endpoint ready." -ForegroundColor Green
        return
    }

    if (-not $RequireAI) {
        Write-Host "[WARN] Ollama is unavailable; startup will continue in deterministic SOC mode." -ForegroundColor Yellow
        return
    }

    Write-Host "[INFO] Ollama unavailable; attempting local Ollama startup..." -ForegroundColor Yellow
    $ollama = Get-Command ollama.exe -ErrorAction SilentlyContinue
    $ollamaPath = $null

    if ($null -ne $ollama) {
        $ollamaPath = $ollama.Source
    } else {
        $candidate = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
        if (Test-Path -LiteralPath $candidate) {
            $ollamaPath = $candidate
        }
    }

    if (-not $ollamaPath) {
        throw "Ollama is required but ollama.exe could not be located."
    }

    Start-Process -FilePath $ollamaPath -ArgumentList @("serve") -WindowStyle Hidden | Out-Null
    if (-not (Wait-OllamaReady -Seconds $OllamaStartupTimeoutSeconds)) {
        throw "Ollama did not become ready within $OllamaStartupTimeoutSeconds seconds."
    }

    Write-Host "[OK] Ollama started and endpoint is ready." -ForegroundColor Green
}

if (-not (Test-Path -LiteralPath $EnvFile)) { throw "Missing runtime env: $EnvFile" }
if (-not (Test-Path -LiteralPath $Compose)) { throw "Missing compose file: $Compose" }
if (-not (Test-Path -LiteralPath $Check)) { throw "Missing health checker: $Check" }

Ensure-DockerReady
Ensure-OllamaReady

$dockerArgs = @("compose","-p",$ProjectName)
if (-not $CoreOnly) {
    $dockerArgs += @("--profile","observability")
}
$dockerArgs += @(
    "--env-file",$EnvFile,
    "-f",$Compose,
    "up","-d"
)
if ($Build) {
    $dockerArgs += "--build"
}
$dockerArgs += @("postgres","redis","api","worker","frontend")
if (-not $CoreOnly) {
    $dockerArgs += @("prometheus","grafana","postgres_exporter","redis_exporter")
}

Write-Host "Starting ThreatLens local production runtime..." -ForegroundColor Cyan
& docker.exe @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "Docker Compose startup failed." }

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$coreReady = $false
do {
    Start-Sleep -Seconds 5
    $checkArgs = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$Check)
    if (-not $CoreOnly) { $checkArgs += "-RequireObservability" }

    & powershell.exe @checkArgs
    if ($LASTEXITCODE -eq 0) {
        $coreReady = $true
        break
    }
} while ((Get-Date) -lt $deadline)

if (-not $coreReady) {
    throw "ThreatLens did not reach required core health within $TimeoutSeconds seconds."
}

if ($RequireAI) {
    Write-Host ""
    Write-Host "Running one final full AI/RAG readiness acceptance..." -ForegroundColor Cyan
    $aiCheckArgs = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$Check,"-RequireAI")
    if (-not $CoreOnly) { $aiCheckArgs += "-RequireObservability" }
    & powershell.exe @aiCheckArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ThreatLens core is healthy but required AI/RAG readiness failed."
    }
}

Write-Host ""
Write-Host "ThreatLens is ready." -ForegroundColor Green
Write-Host "SOC Console : http://127.0.0.1:8080" -ForegroundColor Cyan
if (-not $CoreOnly) {
    Write-Host "Prometheus  : http://127.0.0.1:9090" -ForegroundColor Cyan
    Write-Host "Grafana     : http://127.0.0.1:3000" -ForegroundColor Cyan
}
if ($RequireAI) {
    Write-Host "AI / RAG    : READY (live smoke passed)" -ForegroundColor Cyan
}
exit 0