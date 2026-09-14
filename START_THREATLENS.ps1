param(
    [switch]$CoreOnly,
    [switch]$Build,
    [int]$TimeoutSeconds = 240
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Project ".env.batch7.local"
$Compose = Join-Path $Project "compose.batch7.yml"
$Check = Join-Path $Project "CHECK_THREATLENS.ps1"
$ProjectName = "threatlens-batch7"

if (-not (Test-Path -LiteralPath $EnvFile)) { throw "Missing runtime env: $EnvFile" }
if (-not (Test-Path -LiteralPath $Compose)) { throw "Missing compose file: $Compose" }
if (-not (Test-Path -LiteralPath $Check)) { throw "Missing health checker: $Check" }

& cmd.exe /d /c "docker info >nul 2>nul"
if ($LASTEXITCODE -ne 0) { throw "Docker engine is not ready. Start Docker Desktop and retry." }

$dockerArgs = @(
    "compose","-p",$ProjectName
)
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
do {
    Start-Sleep -Seconds 5
    $checkArgs = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$Check)
    if (-not $CoreOnly) { $checkArgs += "-RequireObservability" }
    & powershell.exe @checkArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "ThreatLens is ready." -ForegroundColor Green
        Write-Host "SOC Console : http://127.0.0.1:8080" -ForegroundColor Cyan
        if (-not $CoreOnly) {
            Write-Host "Prometheus  : http://127.0.0.1:9090" -ForegroundColor Cyan
            Write-Host "Grafana     : http://127.0.0.1:3000" -ForegroundColor Cyan
        }
        exit 0
    }
} while ((Get-Date) -lt $deadline)

throw "ThreatLens did not reach the required health state within $TimeoutSeconds seconds."