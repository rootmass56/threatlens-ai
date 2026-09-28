
param(
    [switch]$SkipFrontendInstall,
    [switch]$SkipDockerConfig
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$python = Join-Path $project ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "ThreatLens Batch-5 virtual environment not found: $python"
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "THREATLENS BATCH 5 - STATIC RELEASE GATE" -ForegroundColor Cyan
Write-Host "PostgreSQL/pgvector + durable AI jobs + Redis worker + React async UX" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

Write-Host "`n[1/7] Python compile..." -ForegroundColor Yellow
& $python -m compileall -q api database jobs rag scripts
if ($LASTEXITCODE -ne 0) { throw "Python compile failed." }
Write-Host "[OK] Python compile PASS" -ForegroundColor Green

Write-Host "`n[2/7] Ruff format check..." -ForegroundColor Yellow
& $python -m ruff format --check `
    jobs `
    api/routes/jobs.py `
    api/routes/system.py `
    api/main.py `
    api/middleware.py `
    database/models.py `
    tests/test_batch5_production_foundation.py `
    tests/test_v010_grounded_rag.py
if ($LASTEXITCODE -ne 0) { throw "Ruff formatting check failed." }
Write-Host "[OK] Ruff format PASS" -ForegroundColor Green

Write-Host "`n[3/7] Ruff lint..." -ForegroundColor Yellow
& $python -m ruff check `
    jobs `
    api/routes/jobs.py `
    api/routes/system.py `
    api/main.py `
    api/middleware.py `
    database/models.py `
    tests/test_batch5_production_foundation.py `
    tests/test_v010_grounded_rag.py
if ($LASTEXITCODE -ne 0) { throw "Ruff lint failed." }
Write-Host "[OK] Ruff lint PASS" -ForegroundColor Green

Write-Host "`n[4/7] Batch-5 and frozen Batch-4 critical regressions..." -ForegroundColor Yellow
& $python -m pytest -q `
    tests/test_batch5_production_foundation.py `
    "tests/test_v010_grounded_rag.py::test_runtime_query_is_grounded_persisted_and_audited" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_profile_residency_hooks_and_deterministic_seed" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_accepts_complete_valid_json_even_if_done_reason_is_length" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_classifies_context_length_exhaustion" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_normalizes_safe_list_shape_variants" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_canonicalizes_noisy_local_json_shape" `
    "tests/test_v010_grounded_rag.py::test_ollama_generator_drops_malformed_optional_claim_shapes_conservatively" `
    "tests/test_v011_adaptive_rag.py::test_v011_guarded_long_deep_failure_skips_stacked_standard_request" `
    "tests/test_v011_adaptive_rag.py::test_v011_both_model_generation_failures_use_deterministic_grounded_fallback" `
    "tests/test_v011_adaptive_rag.py::test_v011_prompt_injection_is_blocked_before_either_model"
if ($LASTEXITCODE -ne 0) {
    throw "Batch-5/frozen Batch-4 regression gate failed. If the error says a data/sample_logs/*.log file is missing, the project was created from the clean source archive instead of the installer-cloned local frozen project."
}
Write-Host "[OK] Python regression gate PASS" -ForegroundColor Green

Write-Host "`n[5/7] OpenAPI/migration/deployment source contract..." -ForegroundColor Yellow
$oldSecret = $env:THREATLENS_JWT_SECRET
try {
    $env:THREATLENS_JWT_SECRET = "batch5-static-verifier-0123456789abcdef0123456789abcdef"
    & $python -m scripts.verify_batch5_release
    if ($LASTEXITCODE -ne 0) { throw "Batch-5 static release contract failed." }
}
finally {
    $env:THREATLENS_JWT_SECRET = $oldSecret
}

$heads = (& $python -m alembic heads 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Alembic heads check failed.`n$heads" }
if ($heads -notmatch "e9b5a1300001" -or ($heads -split "`n").Count -ne 1) {
    throw "Expected one Alembic head e9b5a1300001. Found:`n$heads"
}
Write-Host "[OK] Alembic head PASS: e9b5a1300001" -ForegroundColor Green

Write-Host "`n[6/7] React typecheck/build..." -ForegroundColor Yellow
$frontend = Join-Path $project "frontend"
Push-Location $frontend
try {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        throw "npm is required for the Batch-5 frontend verification. Install Node.js 22 LTS/current-compatible runtime first."
    }
    if (-not $SkipFrontendInstall -and -not (Test-Path "node_modules")) {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
    }
    npm run typecheck
    if ($LASTEXITCODE -ne 0) { throw "React TypeScript typecheck failed." }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "React production build failed." }
}
finally {
    Pop-Location
}
Write-Host "[OK] React build PASS" -ForegroundColor Green

Write-Host "`n[7/7] Docker Compose contract..." -ForegroundColor Yellow
if ($SkipDockerConfig) {
    Write-Host "[SKIP] Docker Compose config explicitly skipped." -ForegroundColor Yellow
}
elseif (Get-Command docker -ErrorAction SilentlyContinue) {
    & docker compose -f deploy/compose/legacy/batch5.yml config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose Batch-5 configuration is invalid." }
    Write-Host "[OK] Docker Compose config PASS" -ForegroundColor Green
}
else {
    throw "Docker is required for the Batch-5 production-foundation release gate. Install Docker Desktop or rerun only for source inspection with -SkipDockerConfig."
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "THREATLENS BATCH 5 STATIC RELEASE GATE: PASS" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "Next: .\scripts\start_batch5_stack.ps1, then .\scripts\initialize_batch5_rag.ps1, then .\scripts\verify_batch5_live.ps1" -ForegroundColor Cyan
