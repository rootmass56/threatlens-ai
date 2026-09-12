param(
    [switch]$SkipFrontendInstall,
    [switch]$SkipDockerConfig,
    [switch]$FullPytest
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$python = Join-Path $project ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { $python = "python" }
$env:THREATLENS_JWT_SECRET = "batch7-static-release-secret-that-is-long-enough-123456789"

Write-Host "THREATLENS BATCH 7 - STATIC RELEASE GATE" -ForegroundColor Cyan

& $python -m compileall -q api database jobs rag scripts advanced_soc core app correlation attack ops migrations
if ($LASTEXITCODE -ne 0) { throw "Python compile failed." }

& $python -m scripts.verify_dependency_security
if ($LASTEXITCODE -ne 0) { throw "Reviewed dependency contract failed." }
& $python -m scripts.generate_source_sbom
if ($LASTEXITCODE -ne 0) { throw "Source SBOM generation failed." }
& $python -m ops.security.batch7_security_audit
if ($LASTEXITCODE -ne 0) { throw "Batch-7 static security audit failed." }
& $python -m scripts.verify_batch7_release
if ($LASTEXITCODE -ne 0) { throw "Batch-7 release contract failed." }

& $python -m pytest -q tests/test_batch7_operational_hardening.py tests/test_batch6_advanced_soc.py
if ($LASTEXITCODE -ne 0) { throw "Batch-7/Batch-6 focused regression failed." }

if ($FullPytest) {
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Complete regression suite failed." }
}

if (-not $SkipFrontendInstall) {
    Push-Location frontend
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
        npm run typecheck
        if ($LASTEXITCODE -ne 0) { throw "Frontend typecheck failed." }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }
    }
    finally { Pop-Location }
}

if (-not $SkipDockerConfig) {
    $envFile = Join-Path $project ".env.batch7.local"
    if (-not (Test-Path -LiteralPath $envFile)) { & (Join-Path $PSScriptRoot "bootstrap_batch7_env.ps1") }
    & docker.exe compose --profile observability --env-file $envFile -f compose.batch7.yml config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Batch-7 Docker Compose validation failed." }
}

Write-Host "THREATLENS BATCH 7 STATIC RELEASE GATE: PASS" -ForegroundColor Green
