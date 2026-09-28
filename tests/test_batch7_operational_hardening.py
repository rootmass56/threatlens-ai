from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault(
    "THREATLENS_JWT_SECRET", "batch7-test-secret-that-is-long-enough-123456789"
)

from api.config import SecuritySettings
from api.main import _non_negative_pool_gauge, create_app
from api.version import THREATLENS_VERSION
from core.observability import JsonLogFormatter, MetricsRegistry
from scripts.verify_internet_demo import tunnel_base_url

ROOT = Path(__file__).resolve().parents[1]


def test_public_demo_verifier_requires_exact_tunnel_origin() -> None:
    assert tunnel_base_url("https://demo.trycloudflare.com") == "https://demo.trycloudflare.com/"
    for value in (
        "http://demo.trycloudflare.com",
        "https://example.com/.trycloudflare.com/",
        "https://demo.trycloudflare.com.evil.example/",
        "https://user@demo.trycloudflare.com/",
        "https://demo.trycloudflare.com/path",
        "https://demo.trycloudflare.com:8443/",
    ):
        with pytest.raises(RuntimeError):
            tunnel_base_url(value)


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


def test_batch7_pool_gauges_are_never_negative() -> None:
    assert _non_negative_pool_gauge(-5) == 0.0
    assert _non_negative_pool_gauge(0) == 0.0
    assert _non_negative_pool_gauge(3) == 3.0
    assert _non_negative_pool_gauge(2.5) == 2.5


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

    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
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
    for source in (backup, smoke, restore):
        assert "function Invoke-Docker" in source
        assert '$ErrorActionPreference = "Continue"' in source
        assert "2> $stderrPath" in source
        assert "ExitCode" in source


def test_batch7_load_probe_is_bounded_and_reports_percentiles() -> None:
    source = (ROOT / "ops/load/batch7_load.py").read_text(encoding="utf-8")
    assert "20_000" in source
    assert "500" in source
    assert '"p95"' in source and '"p99"' in source
    assert "success_rate" in source and "throughput_rps" in source


def test_batch7_supply_chain_and_cicd_assets_exist() -> None:
    ci = (ROOT / ".github/workflows/batch7-ci.yml").read_text(encoding="utf-8")
    assert "gitleaks/gitleaks-action" in ci
    secret_scan_permissions = (
        "  secret-scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "      pull-requests: read\n"
        "    steps:\n"
    )
    assert secret_scan_permissions in ci
    assert "pip-audit" in ci
    assert "aquasecurity/trivy-action" in ci
    assert "scripts.generate_source_sbom" in ci
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    assert "github/codeql-action" in codeql
    ghcr = (ROOT / ".github/workflows/batch7-ghcr.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in ghcr
    assert "          registry: ghcr.io" in ghcr.splitlines()
    assert "github.sha" in ghcr
    # Production image metadata boundary: source/dev/test evidence stays outside /app.
    dockerignore = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    for pattern in (
        "requirements-dev.txt",
        "constraints-*.txt",
        "pyproject.toml",
        "pytest.ini",
        "sbom/",
        "tests/",
    ):
        assert pattern in dockerignore
    release_verifier = (ROOT / "scripts/verify_batch7_release.py").read_text(encoding="utf-8")
    assert 'if not containerized:\n        sbom = json.loads(' in release_verifier
    assert "httpx2==2.13.1" in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert '"httpx2==2.13.1"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_batch7_reviewed_dependency_and_sbom_contract() -> None:
    baseline = json.loads((ROOT / "config/dependency_security_baseline.json").read_text())
    assert baseline["release"] == "0.14.0"
    assert baseline["runtime"]["redis"] == "8.1.0"
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
    assert "continues safely in the background" in system
    assert "Status refreshes automatically" in system
    assert "window.setInterval" in system
    assert "location /api/" in nginx
    assert "location = /api/v1/rag/knowledge/reindex" not in nginx
    assert "proxy_read_timeout 120s" in nginx
    assert "location /internal/" not in nginx

    server_prefix, after_api = nginx.split("location /api/ {", 1)
    api_location, static_location = after_api.split("location / {", 1)
    security_headers = (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Content-Security-Policy",
    )
    for header in security_headers:
        assert f"add_header {header}" not in server_prefix
        assert f"add_header {header}" not in api_location
        assert f"add_header {header}" in static_location


def test_batch7_knowledge_reindex_is_non_blocking_and_status_remains_available() -> None:
    route = (ROOT / "api/routes/rag.py").read_text(encoding="utf-8")
    indexing = (ROOT / "rag/indexing.py").read_text(encoding="utf-8")
    assert "Thread(" in route
    assert 'name="threatlens-knowledge-reindex"' in route
    assert "daemon=True" in route
    assert "runner.start()" in route
    assert "rag.knowledge_reindex.started" in route
    assert "rag.knowledge_reindex.completed" in route
    assert "status_code=status.HTTP_202_ACCEPTED" in route
    assert '"reindex": _reindex_snapshot()' in route
    status_source = indexing.split("    def status(self) -> dict:", 1)[1]
    assert "with self._lock:" not in status_source
    assert "last known-good snapshot" in status_source


def test_batch7_reindex_runner_completes_and_closes_its_session(monkeypatch) -> None:
    import api.routes.rag as rag_route

    class FakeSession:
        committed = False
        rolled_back = False
        closed = False

        def commit(self) -> None:
            self.committed = True

        def rollback(self) -> None:
            self.rolled_back = True

        def close(self) -> None:
            self.closed = True

    result = SimpleNamespace(
        status="unchanged",
        knowledge_version="knowledge-v1",
        documents_seen=2,
        documents_added_or_updated=0,
        documents_removed=0,
        chunks_upserted=0,
        chunks_deleted=0,
        indexed_chunks=10,
    )
    session = FakeSession()
    audit_events: list[dict] = []

    class FakePersistence:
        def __init__(self, supplied_session) -> None:
            assert supplied_session is session

        def record_audit_event(self, **payload) -> None:
            audit_events.append(payload)

    monkeypatch.setattr(rag_route, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        rag_route,
        "get_rag_runtime",
        lambda: SimpleNamespace(
            indexer=SimpleNamespace(index=lambda supplied_session, force: result)
        ),
    )
    monkeypatch.setattr(rag_route, "ThreatLensPersistenceService", FakePersistence)
    with rag_route._REINDEX_STATE_LOCK:
        rag_route._REINDEX_STATE["state"] = "idle"

    assert rag_route._reserve_reindex(force=False) is True
    rag_route._run_rag_reindex(force=False, actor="unit-admin")

    snapshot = rag_route._reindex_snapshot()
    assert snapshot["state"] == "completed"
    assert snapshot["result_status"] == "unchanged"
    assert snapshot["indexed_chunks"] == 10
    assert session.committed is True
    assert session.rolled_back is False
    assert session.closed is True
    assert audit_events[0]["actor"] == "unit-admin"


def test_batch7_reindex_runner_reports_session_start_failure(monkeypatch) -> None:
    import api.routes.rag as rag_route

    def unavailable_session():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(rag_route, "SessionLocal", unavailable_session)
    with rag_route._REINDEX_STATE_LOCK:
        rag_route._REINDEX_STATE["state"] = "idle"

    assert rag_route._reserve_reindex(force=False) is True
    rag_route._run_rag_reindex(force=False, actor="unit-admin")

    snapshot = rag_route._reindex_snapshot()
    assert snapshot["state"] == "failed"
    assert snapshot["completed_utc"] is not None


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
    acceptance = (ROOT / "docs/releases/BATCH7_ACCEPTANCE_CHECKLIST.md").read_text(encoding="utf-8")
    for phase in ("7A", "7B", "7C", "7D", "7E", "7F", "7G", "7H"):
        assert phase in acceptance


def test_repository_layout_exposes_only_current_operator_entrypoints() -> None:
    for path in (
        "compose.yaml",
        "START_THREATLENS.ps1",
        "STOP_THREATLENS.ps1",
        "CHECK_THREATLENS.ps1",
        "scripts/demo/start-golden-demo.ps1",
        "scripts/demo/start-enhanced-demo-v2.ps1",
        "scripts/demo/start-internet-demo.ps1",
        "scripts/demo/stop-internet-demo.ps1",
        "deploy/compose/internet-demo.override.yml",
        "deploy/compose/legacy/batch5.yml",
        "deploy/compose/legacy/batch6.yml",
        "docs/releases/BATCH7_ACCEPTANCE_CHECKLIST.md",
        "release/RELEASE_MANIFEST_v0.14.0.json",
    ):
        assert (ROOT / path).is_file(), path

    for retired_root_path in (
        "compose.batch5.yml",
        "compose.batch6.yml",
        "compose.batch7.yml",
        "compose.phase9.internet.yml",
        "START_THREATLENS_DEMO.ps1",
        "START_THREATLENS_ENHANCED_DEMO_V2.ps1",
        "START_THREATLENS_INTERNET_DEMO.ps1",
        "STOP_THREATLENS_INTERNET_DEMO.ps1",
        "BATCH7_ACCEPTANCE_CHECKLIST.md",
        "RELEASE_MANIFEST_v0.14.0.json",
    ):
        assert not (ROOT / retired_root_path).exists(), retired_root_path
