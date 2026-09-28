$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch6.local"
if (-not (Test-Path $envFile)) { & (Join-Path $PSScriptRoot "bootstrap_batch6_env.ps1") }
docker compose --env-file $envFile -f deploy/compose/legacy/batch6.yml up --build -d postgres redis api worker frontend
if ($LASTEXITCODE -ne 0) { throw "Batch 6 stack startup failed." }
Write-Host "ThreatLens Batch 6 is starting at http://127.0.0.1:8080" -ForegroundColor Green
Write-Host "Run .\scripts\verify_batch6_live.ps1 after containers become healthy." -ForegroundColor Cyan
