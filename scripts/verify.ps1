$ErrorActionPreference = "Stop"

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor DarkGray
    Write-Host $Description -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor DarkGray

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }

    Write-Host "$Description passed." -ForegroundColor Green
}

if (Test-Path ".venv\Scripts\Activate.ps1") {
    .\.venv\Scripts\Activate.ps1
}

Write-Host ""
Write-Host "ThreatLens AI v0.12.0 Production Web Verification Suite" -ForegroundColor Green
Write-Host "Project: $PWD"
Write-Host "Python: $(python --version 2>&1)"
$ruleProfile = $env:THREATLENS_RULE_PROFILE
if ([string]::IsNullOrWhiteSpace($ruleProfile)) {
    $ruleProfile = "default"
}
Write-Host "Rule profile: $ruleProfile"
Write-Host "ATT&CK target: v19.1 all domains - Enterprise, Mobile and ICS"

Invoke-CheckedCommand -Description "Compiling Python source" -Command {
    python -m compileall api app attack config correlation core database migrations rag rules tests scripts
}

Invoke-CheckedCommand -Description "Running Ruff code-quality checks" -Command {
    ruff check api app attack config correlation core database rag rules tests scripts migrations\env.py
}

Invoke-CheckedCommand -Description "Checking Ruff formatting" -Command {
    ruff format api app attack config correlation core database rag rules tests scripts migrations\env.py --check
}

Invoke-CheckedCommand -Description "Verifying reviewed dependency security baseline" -Command {
    python -m scripts.verify_dependency_security --installed
}

Invoke-CheckedCommand -Description "Capturing transitive dependency lock and CycloneDX SBOM" -Command {
    python -m scripts.generate_dependency_attestation
}

if ($env:THREATLENS_REQUIRE_ONLINE_DEPENDENCY_AUDIT -eq "1") {
    Invoke-CheckedCommand -Description "Checking exact dependency lock against OSV" -Command {
        python -m scripts.audit_dependencies_osv
    }
}
else {
    Write-Host "Online OSV dependency audit skipped (set THREATLENS_REQUIRE_ONLINE_DEPENDENCY_AUDIT=1 to require it)." -ForegroundColor Yellow
}

Invoke-CheckedCommand -Description "Running governed automated test matrix" -Command {
    python -m scripts.verify_test_matrix
}

Invoke-CheckedCommand -Description "Checking Alembic migration consistency" -Command {
    alembic check
}

Invoke-CheckedCommand -Description "Checking active Alembic revision" -Command {
    alembic current
}

Invoke-CheckedCommand -Description "Confirming v0.12.0 Alembic head" -Command {
    python -c "from sqlalchemy import text; from database.session import engine; c=engine.connect(); v=c.execute(text('SELECT version_num FROM alembic_version')).scalar_one(); c.close(); assert v=='d4a7c0e51010', v; print('Alembic head:',v)"
}

Invoke-CheckedCommand -Description "Validating 42 governed rules and 126 fixtures" -Command {
    python -m scripts.verify_detection_catalog
}

Invoke-CheckedCommand -Description "Validating complete ATT&CK v19.1 all-domain catalogs and Enterprise mappings" -Command {
    python -m scripts.verify_attack_catalog
}

Invoke-CheckedCommand -Description "Checking connector auto-detection and normalization" -Command {
    python -m scripts.verify_connectors
}

Invoke-CheckedCommand -Description "Validating advanced correlation and attack graphs" -Command {
    python -m scripts.verify_advanced_correlation
}

Invoke-CheckedCommand -Description "Validating FastAPI authentication, RBAC and API security" -Command {
    python -m scripts.verify_security_api
}

Invoke-CheckedCommand -Description "Validating grounded RAG retrieval, grounding and safety controls" -Command {
    python -m scripts.verify_rag
}

Invoke-CheckedCommand -Description "Validating advanced hybrid RAG planning, exact retrieval and citation planes" -Command {
    python -m scripts.verify_advanced_rag
}

Invoke-CheckedCommand -Description "Validating v0.12 adaptive model routing and profile governance" -Command {
    python -m scripts.verify_adaptive_rag
}

if ($env:THREATLENS_REQUIRE_RAG_READY -eq "1") {
    Invoke-CheckedCommand -Description "Checking live ThreatLens SQLite vector store and Ollama RAG runtime" -Command {
        python -m scripts.verify_rag_runtime --require-ready
    }
}
else {
    Write-Host "Live Ollama/SQLite-vector readiness gate skipped (set THREATLENS_REQUIRE_RAG_READY=1 to require it)." -ForegroundColor Yellow
}

Invoke-CheckedCommand -Description "Checking validated Linux regression pipeline" -Command {
    python -c "from pathlib import Path; from core.pipeline import analyze_linux_auth_log; p=analyze_linux_auth_log(Path('data/sample_logs/auth_sample.log').read_text(encoding='utf-8-sig')); assert (p.event_count,p.alert_count,p.incident_count,p.quarantined_count)==(9,4,1,0); print('Linux sample:',p.event_count,p.alert_count,p.incident_count,p.quarantined_count)"
}

Invoke-CheckedCommand -Description "Checking v0.12.0 multi-source regression pipeline" -Command {
    python -c "from pathlib import Path; from core.pipeline import SourceInput,analyze_sources; d=Path('data/sample_logs'); n=['windows_security_sample.jsonl','sysmon_sample.jsonl','suricata_eve_sample.jsonl','zeek_conn_sample.log','zeek_dns_sample.log']; p=analyze_sources([SourceInput(raw_content=(d/x).read_bytes(),filename=x) for x in n]); assert (p.event_count,p.alert_count,p.incident_count,p.quarantined_count)==(22,8,2,0); assert set(p.connector_ids)=={'windows_security','windows_sysmon','suricata_eve','zeek'}; print('Multi-source sample:',p.event_count,p.alert_count,p.incident_count,p.quarantined_count,p.connector_ids)"
}

Invoke-CheckedCommand -Description "Checking ThreatLens package imports and OpenAPI contract" -Command {
    python -m scripts.verify_package_contract
}


Invoke-CheckedCommand -Description "Verifying Streamlit-to-React SOC feature parity" -Command {
    python -m scripts.verify_frontend_feature_parity
}

Invoke-CheckedCommand -Description "Verifying React/Vite production frontend" -Command {
    & .\scripts\verify_frontend.ps1
}

Invoke-CheckedCommand -Description "Checking repository security hygiene" -Command {
    python -m scripts.verify_repository_hygiene
}

Invoke-CheckedCommand -Description "Verifying v0.12.0 release manifest integrity" -Command {
    python -m scripts.verify_release_manifest
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "All ThreatLens AI v0.12.0 verification checks passed." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
