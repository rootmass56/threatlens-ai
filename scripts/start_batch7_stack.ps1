param(
    [switch]$Observability
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.batch7.yml"

if (-not (Test-Path -LiteralPath $envFile)) {
    & (Join-Path $PSScriptRoot "bootstrap_batch7_env.ps1")
}

$args = @("compose")
if ($Observability) { $args += @("--profile","observability") }
$args += @("--env-file",$envFile,"-f",$compose,"up","--build","-d","postgres","redis","api","worker","frontend")
if ($Observability) { $args += @("prometheus","grafana","postgres_exporter","redis_exporter") }

& docker.exe @args
if ($LASTEXITCODE -ne 0) { throw "Batch-7 Docker startup failed." }

Write-Host "ThreatLens Batch 7 startup requested." -ForegroundColor Green
Write-Host "UI: http://127.0.0.1:8080" -ForegroundColor Cyan
if ($Observability) {
    Write-Host "Prometheus: http://127.0.0.1:9090" -ForegroundColor Cyan
    Write-Host "Grafana: http://127.0.0.1:3000" -ForegroundColor Cyan
}
