param([switch]$SkipFrontendInstall,[switch]$SkipDockerConfig)
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$python = Join-Path $project ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }
$env:THREATLENS_JWT_SECRET = "batch6-static-release-secret-that-is-long-enough-123456789"
Write-Host "THREATLENS BATCH 6 - STATIC RELEASE GATE" -ForegroundColor Cyan
& $python -m compileall -q api database jobs rag scripts advanced_soc core app correlation attack
if ($LASTEXITCODE -ne 0) { throw "Python compile failed." }
& $python -m pytest -q tests/test_batch6_advanced_soc.py
if ($LASTEXITCODE -ne 0) { throw "Batch-6 governed test suite failed." }
& $python -m scripts.verify_batch6_release
if ($LASTEXITCODE -ne 0) { throw "Batch-6 release contract failed." }
if (-not $SkipFrontendInstall) {
    Push-Location frontend
    try { npm ci; if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }; npm run typecheck; if ($LASTEXITCODE -ne 0) { throw "Frontend typecheck failed." }; npm run build; if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." } } finally { Pop-Location }
}
if (-not $SkipDockerConfig) {
    $envFile = Join-Path $project ".env.batch6.local"
    if (-not (Test-Path $envFile)) { throw "Run scripts/bootstrap_batch6_env.ps1 before Docker config verification." }
    docker compose --env-file $envFile -f compose.batch6.yml config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Batch-6 Docker Compose validation failed." }
}
Write-Host "THREATLENS BATCH 6 STATIC RELEASE GATE: PASS" -ForegroundColor Green
