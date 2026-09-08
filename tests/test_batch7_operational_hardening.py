from __future__ import annotations

import json
import logging
import os
from pathlib import Path

os.environ.setdefault(
    "THREATLENS_JWT_SECRET", "batch7-test-secret-that-is-long-enough-123456789"
)

from api.config import SecuritySettings
from api.main import create_app
from api.version import THREATLENS_VERSION
from core.observability import JsonLogFormatter, MetricsRegistry

ROOT = Path(__file__).resolve().parents[1]


def test_batch7_current_release_version_and_frontend() -> None:
    assert THREATLENS_VERSION == "0.14.0"
    assert 'version = "0.14.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    assert package["version"] == "0.14.0"
    assert "v0.14.0" in (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")


def test_batch7_security_settings_have_operational_defaults(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_JWT_SECRET", "x" * 40)
    for name in (
        "THREATLENS_STRUCTURED_LOGGING",
        "THREATLENS_METRICS_ENABLED",
        "THREATLENS_SLOW_REQUEST_MS",
        "THREATLENS_HTTPS_ONLY",
        "THREATLENS_MAX_REQUEST_BODY_BYTES",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = SecuritySettings.from_environment()
    assert settings.structured_logging is False
    assert settings.metrics_enabled is True
    assert settings.slow_request_ms == 1000
    assert settings.https_only is False
    assert settings.max_request_body_bytes == 120 * 1024 * 1024


def test_batch7_metrics_registry_exports_prometheus_histogram() -> None:
    registry = MetricsRegistry()
    registry.inc("threatlens_test_total", labels={"scope": "unit"})
    registry.set_gauge("threatlens_test_gauge", 2)
    registry.observe(
        "threatlens_test_seconds",
        0.05,
        spec=MetricsRegistry.HTTP_DURATION,
        labels={"route": "/unit"},
    )
    text = registry.render_prometheus()
    assert 'threatlens_test_total{scope="unit"} 1' in text
    assert "threatlens_test_gauge 2" in text
    assert "threatlens_test_seconds_bucket" in text
    assert "threatlens_test_seconds_count" in text


def test_batch7_json_log_formatter_is_machine_parseable() -> None:
    record = logging.LogRecord(
        "threatlens.test", logging.INFO, __file__, 10, "hello %s", ("soc",), None
    )
    record.request_id = "request-123"
    record.event = "unit.test"
    payload = json.loads(JsonLogFormatter().format(record))
    assert payload["message"] == "hello soc"
    assert payload["request_id"] == "request-123"
    assert payload["event"] == "unit.test"
    assert payload["level"] == "INFO"


def _settings(**overrides) -> SecuritySettings:
    values = dict(
        jwt_secret="z" * 40,
        jwt_issuer="threatlens-ai",
        jwt_audience="threatlens-api",
        access_token_minutes=15,
        refresh_token_hours=8,
        max_failed_logins=5,
        lockout_minutes=15,
        allowed_origins=("http://127.0.0.1:8080",),
        trusted_hosts=("testserver", "127.0.0.1"),
        enable_development_docs=False,
        max_upload_bytes=10 * 1024 * 1024,
        max_upload_files=10,
        api_host="127.0.0.1",
        api_port=8000,
    )
    values.update(overrides)
    return SecuritySettings(**values)


def test_batch7_internal_metrics_is_not_in_public_openapi() -> None:
    app = create_app(_settings())
    schema = app.openapi()
    assert "/internal/metrics" not in schema["paths"]
    assert "/api/v1/system/observability" in schema["paths"]


def test_batch7_request_body_and_hsts_controls_exist() -> None:
    source = (ROOT / "api/middleware.py").read_text(encoding="utf-8")
    assert "RequestBodyLimitMiddleware" in source
    assert "request_too_large" in source
    assert "Strict-Transport-Security" in source
    assert "Cross-Origin-Opener-Policy" in source
    assert "Cross-Origin-Resource-Policy" in source


def test_batch7_compose_has_private_data_services_and_observability_profile() -> None:
    import yaml

    compose = yaml.safe_load((ROOT / "compose.batch7.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert not services["postgres"].get("ports")
    assert not services["redis"].get("ports")
    assert services["prometheus"]["profiles"] == ["observability"]
    assert services["grafana"]["profiles"] == ["observability"]
    assert services["api"]["cap_drop"] == ["ALL"]
    assert services["worker"]["cap_drop"] == ["ALL"]
    assert any(str(item).startswith("127.0.0.1:8080:") for item in services["frontend"]["ports"])


def test_batch7_monitoring_configs_and_dashboard_are_provisioned() -> None:
    prometheus = (ROOT / "monitoring/prometheus/prometheus.yml").read_text(encoding="utf-8")
    assert "api:10000" in prometheus
    assert "/internal/metrics" in prometheus
    assert "postgres_exporter:9187" in prometheus
    assert "redis_exporter:9121" in prometheus
    dashboard = json.loads(
        (ROOT / "monitoring/grafana/dashboards/threatlens-operations.json").read_text(
            encoding="utf-8"
        )
    )
    assert dashboard["uid"] == "threatlens-operations"
    assert len(dashboard["panels"]) >= 7


def test_batch7_operational_index_migration_chains_from_batch6() -> None:
    source = (
        ROOT / "migrations/versions/b7f1c2d30001_batch7_operational_indexes.py"
    ).read_text(encoding="utf-8")
    assert 'revision: str = "b7f1c2d30001"' in source
    assert 'down_revision: str | None = "f6a6c0b60001"' in source
    for index in (
        "ix_ai_jobs_recovery_scan",
        "ix_audit_logs_entity_created",
        "ix_realtime_ingress_source_received",
        "ix_incident_tasks_assignee_status_due",
    ):
        assert index in source


def test_batch7_backup_restore_is_checksum_guarded_and_primary_restore_blocked() -> None:
    backup = (ROOT / "scripts/backup_batch7.ps1").read_text(encoding="utf-8")
    smoke = (ROOT / "scripts/restore_batch7_smoke.ps1").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/restore_batch7.ps1").read_text(encoding="utf-8")
    assert "Get-FileHash" in backup and "SHA256" in backup
    assert "threatlens_restore_smoke_" in smoke
    assert "pgvector extension missing after restore" in smoke
    assert "AllowPrimaryDatabaseRestore" in restore
    assert "Primary database restore is blocked by default" in restore


def test_batch7_load_probe_is_bounded_and_reports_percentiles() -> None:
    source = (ROOT / "ops/load/batch7_load.py").read_text(encoding="utf-8")
    assert "20_000" in source
    assert "500" in source
    assert '"p95"' in source and '"p99"' in source
    assert "success_rate" in source and "throughput_rps" in source


def test_batch7_supply_chain_and_cicd_assets_exist() -> None:
    ci = (ROOT / ".github/workflows/batch7-ci.yml").read_text(encoding="utf-8")
    assert "gitleaks/gitleaks-action" in ci
    assert "pip-audit" in ci
    assert "aquasecurity/trivy-action" in ci
    assert "scripts.generate_source_sbom" in ci
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    assert "github/codeql-action" in codeql
    ghcr = (ROOT / ".github/workflows/batch7-ghcr.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in ghcr
    assert "ghcr.io" in ghcr
    assert "github.sha" in ghcr


def test_batch7_reviewed_dependency_and_sbom_contract() -> None:
    baseline = json.loads((ROOT / "config/dependency_security_baseline.json").read_text())
    assert baseline["release"] == "0.14.0"
    assert baseline["runtime"]["redis"] == "6.4.0"
    expected = {
        (name, version)
        for scope in ("build", "runtime", "development")
        for name, version in baseline[scope].items()
    }
    assert len(expected) == 27
    sbom = json.loads((ROOT / "sbom/source-dependencies-v0.14.0.cdx.json").read_text())
    actual = {(item["name"], item["version"]) for item in sbom["components"]}
    assert actual == expected
    assert sbom["metadata"]["component"]["version"] == "0.14.0"


def test_batch7_frontend_exposes_observability_without_public_metrics_url() -> None:
    system = (ROOT / "frontend/src/pages/SystemPage.tsx").read_text(encoding="utf-8")
    nginx = (ROOT / "frontend/nginx.conf").read_text(encoding="utf-8")
    assert "/api/v1/system/observability" in system
    assert "Observability" in system
    assert "location /api/" in nginx
    assert "location /internal/" not in nginx


def test_batch7_runbook_and_acceptance_matrix_is_complete() -> None:
    for name in (
        "START_STOP.md",
        "OBSERVABILITY.md",
        "REDIS_OUTAGE.md",
        "WORKER_RECOVERY.md",
        "DATABASE_OUTAGE.md",
        "BACKUP_RESTORE.md",
        "MODEL_OUTAGE.md",
        "DEPLOYMENT_ROLLBACK.md",
        "CREDENTIAL_ROTATION.md",
        "SECURITY_INCIDENT.md",
    ):
        assert (ROOT / "docs/runbooks" / name).exists(), name
    acceptance = (ROOT / "BATCH7_ACCEPTANCE_CHECKLIST.md").read_text(encoding="utf-8")
    for phase in ("7A", "7B", "7C", "7D", "7E", "7F", "7G", "7H"):
        assert phase in acceptance
