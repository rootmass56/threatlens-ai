$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch6.local"
if (-not (Test-Path $envFile)) { throw ".env.batch6.local does not exist." }
$keyLine = Get-Content -LiteralPath $envFile | Where-Object { $_ -like 'THREATLENS_SYSLOG_INGEST_KEY=*' } | Select-Object -First 1
$key = [string]($keyLine -replace '^THREATLENS_SYSLOG_INGEST_KEY=', '')
if ([string]::IsNullOrWhiteSpace($key)) { throw "Create a syslog_rfc ingestion source first, then set THREATLENS_SYSLOG_INGEST_KEY in .env.batch6.local." }
docker compose --profile syslog --env-file $envFile -f compose.batch6.yml up -d syslog_collector
if ($LASTEXITCODE -ne 0) { throw "Syslog collector startup failed." }
Write-Host "ThreatLens UDP syslog collector is listening on port 5514." -ForegroundColor Green
