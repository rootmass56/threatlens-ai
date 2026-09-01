from pathlib import Path

from api.version import THREATLENS_VERSION
from core.connectors import build_default_connector_registry


ROOT = Path(__file__).resolve().parents[1]


def test_v013_release_and_connector_contract() -> None:
    assert THREATLENS_VERSION == "0.13.0"
    assert build_default_connector_registry().connector_ids() == [
        "entra_id",
        "linux_auth",
        "suricata_eve",
        "syslog_rfc",
        "windows_security",
        "windows_sysmon",
        "zeek",
    ]
    assert (ROOT / "README.md").read_text(encoding="utf-8").startswith(
        "# ThreatLens AI v0.13.0"
    )
    assert "## v0.13.0 — Batch 6 Advanced SOC Capability Expansion" in (
        ROOT / "CHANGELOG.md"
    ).read_text(encoding="utf-8")


def test_v013_durable_ai_frontend_contract() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "AiPage.tsx").read_text(
        encoding="utf-8"
    )
    for marker in (
        "/assistant/jobs",
        "Idempotency-Key",
        "/cancel",
        "setInterval",
        "queue_delivery_state",
        "result_query_uuid",
    ):
        assert marker in source
    assert "/assistant/query" not in source


def test_v013_machine_ingestion_is_declared_as_authenticated_openapi_boundary(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api.main import create_app

    schema = create_app().openapi()
    scheme = schema["components"]["securitySchemes"]["ThreatLensIngestKey"]
    assert scheme["type"] == "apiKey"
    assert scheme["in"] == "header"
    assert scheme["name"] == "X-ThreatLens-Ingest-Key"
    operation = schema["paths"]["/api/v1/ingest/realtime"]["post"]
    assert operation["security"] == [{"ThreatLensIngestKey": []}]
