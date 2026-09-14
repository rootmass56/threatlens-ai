param(
    [int]$TimeoutSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Project ".env.batch7.local"
$Compose = Join-Path $Project "compose.batch7.yml"
$ProjectName = "threatlens-batch7"

if (-not (Test-Path -LiteralPath $EnvFile)) { throw "Missing runtime env: $EnvFile" }
if (-not (Test-Path -LiteralPath $Compose)) { throw "Missing compose file: $Compose" }

& cmd.exe /d /c "docker info >nul 2>nul"
if ($LASTEXITCODE -ne 0) { throw "Docker engine is not ready." }

Write-Host "Stopping ThreatLens containers gracefully..." -ForegroundColor Cyan
$dockerArgs = @(
    "compose","-p",$ProjectName,
    "--profile","observability",
    "--profile","syslog",
    "--env-file",$EnvFile,
    "-f",$Compose,
    "stop","-t",$TimeoutSeconds
)
& docker.exe @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "Docker Compose stop failed." }

$running = ((& docker.exe ps --filter "label=com.docker.compose.project=$ProjectName" --format "{{.Names}}" 2>$null | Out-String).Trim())
if ($running) {
    throw "One or more ThreatLens containers remain running:`n$running"
}

$volumes = @(
    (& docker.exe volume ls --format "{{.Name}}" 2>$null | Out-String) -split "`r?`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -match "^threatlens-batch7_threatlens-" }
)
$required = @(
    "threatlens-batch7_threatlens-postgres-data",
    "threatlens-batch7_threatlens-redis-data",
    "threatlens-batch7_threatlens-prometheus-data",
    "threatlens-batch7_threatlens-grafana-data"
)
foreach ($name in $required) {
    if ($volumes -notcontains $name) {
        throw "Persistent volume missing after stop: $name"
    }
}

Write-Host "ThreatLens stopped cleanly. Persistent volumes were preserved." -ForegroundColor Green
Write-Host "No container, network, image, or volume was deleted." -ForegroundColor DarkGray
exit 0