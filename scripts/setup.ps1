$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$activateScript = Join-Path $projectRoot ".venv\Scripts\Activate.ps1"

if (-not (Test-Path $venvPython)) {
    if (Test-Path (Join-Path $projectRoot ".venv")) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupRoot = Join-Path (Split-Path $projectRoot -Parent) "ThreatLensAI_local_backups"
        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
        Move-Item -Path (Join-Path $projectRoot ".venv") -Destination (Join-Path $backupRoot ".venv_incomplete_$timestamp") -Force
    }

    if (Get-Command py -ErrorAction SilentlyContinue) {
        py -3.11 --version
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.11 is required but is not available through the Windows Python launcher."
        }
        py -3.11 -m venv .venv
    }
    elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $version = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        if ($version -ne "3.11") {
            throw "Python 3.11 is required, but the detected version is $version."
        }
        python -m venv .venv
    }
    else {
        throw "Python 3.11 was not found."
    }
}

if (-not (Test-Path $activateScript)) {
    throw "The virtual environment is incomplete: $activateScript is missing."
}

. $activateScript

Invoke-NativeChecked -Description "Python packaging tool installation" -Command { python -m pip install "pip==26.2.1" "setuptools==84.0.0" "wheel==0.47.0" }
Invoke-NativeChecked -Description "Runtime dependency installation" -Command { python -m pip install -r requirements.txt -c constraints-windows-py311.txt }
Invoke-NativeChecked -Description "Development dependency installation" -Command { python -m pip install -r requirements-dev.txt -c constraints-windows-py311.txt }
Invoke-NativeChecked -Description "ThreatLens editable installation" -Command { python -m pip install -c constraints-windows-py311.txt --no-build-isolation -e . }
Invoke-NativeChecked -Description "Alembic migration" -Command { alembic upgrade head }

python -m scripts.bootstrap_security
if ($LASTEXITCODE -ne 0) {
    throw "ThreatLens security bootstrap failed."
}

python -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "Installed Python dependencies are inconsistent."
}

python -m scripts.verify_dependency_security --installed
if ($LASTEXITCODE -ne 0) {
    throw "Reviewed dependency security baseline failed."
}

python -m scripts.generate_dependency_attestation
if ($LASTEXITCODE -ne 0) {
    throw "Dependency lock/SBOM attestation generation failed."
}

if ($env:THREATLENS_SKIP_ATTACK_SYNC -eq "1") {
    Write-Host "Skipping ATT&CK synchronization because THREATLENS_SKIP_ATTACK_SYNC=1." -ForegroundColor Yellow
}
else {
    Write-Host "Synchronizing complete pinned Enterprise, Mobile and ICS ATT&CK v19.1 catalogs..." -ForegroundColor Cyan
    python -m scripts.sync_attack_catalog --actor setup
    if ($LASTEXITCODE -ne 0) {
        throw "ATT&CK v19.1 all-domain synchronization failed. Check network access and rerun setup.ps1."
    }
}

if ($env:THREATLENS_SKIP_RAG_SETUP -eq "1") {
    Write-Host "Skipping external RAG setup because THREATLENS_SKIP_RAG_SETUP=1." -ForegroundColor Yellow
}
elseif (Get-Command ollama -ErrorAction SilentlyContinue) {
    $standardModel = if ($env:THREATLENS_RAG_STANDARD_LLM_MODEL) { $env:THREATLENS_RAG_STANDARD_LLM_MODEL } elseif ($env:THREATLENS_RAG_LLM_MODEL) { $env:THREATLENS_RAG_LLM_MODEL } else { "qwen3.5:4b" }
    $deepModel = if ($env:THREATLENS_RAG_DEEP_LLM_MODEL) { $env:THREATLENS_RAG_DEEP_LLM_MODEL } else { "qwen3.5:9b" }
    $embeddingModel = if ($env:THREATLENS_RAG_EMBEDDING_MODEL) { $env:THREATLENS_RAG_EMBEDDING_MODEL } else { "qwen3-embedding:0.6b" }
    if ($env:THREATLENS_SKIP_RAG_MODEL_PULL -ne "1") {
        Write-Host "Pulling configured local Ollama RAG models..." -ForegroundColor Cyan
        ollama pull $standardModel
        if ($LASTEXITCODE -ne 0) { throw "Ollama Standard model pull failed: $standardModel" }
        if ($deepModel -ne $standardModel) {
            ollama pull $deepModel
            if ($LASTEXITCODE -ne 0) { throw "Ollama Deep Analysis model pull failed: $deepModel" }
        }
        ollama pull $embeddingModel
        if ($LASTEXITCODE -ne 0) { throw "Ollama embedding model pull failed: $embeddingModel" }
    }
    python -m scripts.index_rag_knowledge
    if ($LASTEXITCODE -ne 0) {
        throw "Grounded RAG knowledge indexing failed. Confirm Ollama is running and configured models are installed."
    }
}
else {
    Write-Host "Ollama is not installed or not on PATH. Deterministic ThreatLens remains usable." -ForegroundColor Yellow
    Write-Host "Install Ollama, pull qwen3.5:4b, qwen3.5:9b and qwen3-embedding:0.6b, then run: python -m scripts.index_rag_knowledge" -ForegroundColor Yellow
}

Write-Host "ThreatLens AI v0.12.0 setup completed with dependency security attestation." -ForegroundColor Green
