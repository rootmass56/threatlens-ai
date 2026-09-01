from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from api.config import SecuritySettings, is_unsafe_jwt_secret
from api.routes.analyses import _parse_source_metadata
from api.uploads import safe_upload_filename
from app.api_client import ThreatLensApiClient
from core.pipeline import SourceInput

ROOT_DIR = Path(__file__).resolve().parents[1]


def _minimal_analysis_response() -> dict[str, Any]:
    return {
        "persisted": False,
        "session_uuid": None,
        "duplicate_session_uuid": None,
        "pipeline": {
            "events": [],
            "alerts": [],
            "incidents": [],
            "timeline": [],
            "quarantined": [],
            "source_manifest": [],
            "parser_statistics": {
                "source_count": 0,
                "schema_version": "1.0.0",
                "parse_success_rate": 0.0,
            },
            "connector_ids": [],
            "loaded_rule_count": 0,
            "correlation": None,
        },
    }


def test_known_jwt_placeholders_are_rejected() -> None:
    assert is_unsafe_jwt_secret("")
    assert is_unsafe_jwt_secret("short-secret")
    assert is_unsafe_jwt_secret("replace-with-at-least-32-random-characters")
    assert not is_unsafe_jwt_secret("0123456789abcdef0123456789abcdef0123456789abcdef")


def test_security_settings_reject_known_example_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "THREATLENS_JWT_SECRET",
        "replace-with-at-least-32-random-characters",
    )
    with pytest.raises(RuntimeError, match="non-placeholder"):
        SecuritySettings.from_environment()


def test_env_example_cannot_enable_a_known_jwt_secret() -> None:
    text = (ROOT_DIR / ".env.example").read_text(encoding="utf-8")
    line = next(item for item in text.splitlines() if item.startswith("THREATLENS_JWT_SECRET="))
    assert line == "THREATLENS_JWT_SECRET="


def test_streamlit_secret_file_is_explicitly_ignored() -> None:
    gitignore = (ROOT_DIR / ".gitignore").read_text(encoding="utf-8")
    assert ".streamlit/secrets.toml" in gitignore.splitlines()


def test_ndjson_upload_extension_matches_connector_capabilities() -> None:
    assert safe_upload_filename("telemetry.ndjson") == "telemetry.ndjson"


def test_source_metadata_preserves_connector_override_and_analysis_year() -> None:
    metadata = _parse_source_metadata(
        json.dumps(
            [
                {
                    "connector_id": "linux_auth",
                    "options": {"analysis_year": 2026},
                },
                {
                    "connector_id": "windows_sysmon",
                    "options": {},
                },
            ]
        ),
        file_count=2,
    )
    assert metadata == [
        ("linux_auth", {"analysis_year": 2026}),
        ("windows_sysmon", {}),
    ]


@pytest.mark.parametrize(
    ("payload", "file_count", "error_code"),
    (
        ("not-json", 1, "invalid_source_metadata"),
        (json.dumps([]), 1, "source_metadata_count_mismatch"),
        (
            json.dumps([{"connector_id": "not-registered", "options": {}}]),
            1,
            "unknown_connector",
        ),
        (
            json.dumps([{"connector_id": "linux_auth", "options": {"analysis_year": 1999}}]),
            1,
            "invalid_analysis_year",
        ),
        (
            json.dumps([{"connector_id": "linux_auth", "options": {"unsafe": True}}]),
            1,
            "unsupported_source_option",
        ),
    ),
)
def test_source_metadata_rejects_invalid_or_unsupported_values(
    payload: str,
    file_count: int,
    error_code: str,
) -> None:
    with pytest.raises(HTTPException) as raised:
        _parse_source_metadata(payload, file_count=file_count)
    assert raised.value.detail["code"] == error_code


def test_single_source_api_client_sends_connector_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    client = ThreatLensApiClient(access_token="test-token")

    def fake_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return _minimal_analysis_response()

    monkeypatch.setattr(client, "_request", fake_request)
    client.analyze_and_persist_source(
        analysis_name="Linux override",
        original_filename="auth.log",
        raw_content=b"sample",
        connector_id="linux_auth",
        connector_options={"analysis_year": 2026},
    )

    metadata = json.loads(captured["data"]["source_metadata"])
    assert metadata == [
        {
            "connector_id": "linux_auth",
            "options": {"analysis_year": 2026},
        }
    ]


def test_multi_source_api_client_sends_per_source_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    client = ThreatLensApiClient(access_token="test-token")

    def fake_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return _minimal_analysis_response()

    monkeypatch.setattr(client, "_request", fake_request)
    client.analyze_and_persist_sources(
        analysis_name="Mixed telemetry",
        sources=[
            SourceInput(
                raw_content=b"linux",
                filename="auth.log",
                connector_id="linux_auth",
                options={"analysis_year": 2026},
            ),
            SourceInput(
                raw_content=b"sysmon",
                filename="sysmon.jsonl",
                connector_id="windows_sysmon",
            ),
        ],
    )

    metadata = json.loads(captured["data"]["source_metadata"])
    assert metadata == [
        {
            "connector_id": "linux_auth",
            "options": {"analysis_year": 2026},
        },
        {
            "connector_id": "windows_sysmon",
            "options": {},
        },
    ]


def test_upload_page_uses_remote_pipeline_contract_without_local_parser_properties() -> None:
    source = (ROOT_DIR / "app" / "pages" / "upload.py").read_text(encoding="utf-8")
    assert "pipeline.all_parser_results" not in source
    assert "pipeline.parse_success_rate" not in source
    assert "application_service.security_status()" in source
