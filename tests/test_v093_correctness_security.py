
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import pytest
from sqlalchemy import select

from api.middleware import InMemoryRateLimiter, RateLimitMiddleware, RateLimitPolicy
from app.application_service import AnalysisExecutionResult
from core.pipeline import AnalysisPipelineResult
from core.report_generator import generate_incident_report
from database.exceptions import InvalidIncidentStateError
from database.models import UserAccountModel
from tests.test_application_service import application_service as _base_application_service
from tests.test_v09_security_api import (
    auth_header,
    login,
)
from tests.test_v09_security_api import (
    security_environment as _base_security_environment,
)


@pytest.fixture(name="application_service")
def _application_service_fixture():
    yield from _base_application_service.__wrapped__()


@pytest.fixture(name="security_environment")
def _security_environment_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    yield from _base_security_environment.__wrapped__(tmp_path, monkeypatch)


SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def test_semantic_duplicate_fingerprint_distinguishes_analysis_year(application_service) -> None:
    content = SAMPLE_LOG_PATH.read_bytes()
    first = application_service.analyze_and_persist_source(
        analysis_name="Linux 2025",
        original_filename="auth.log",
        raw_content=content,
        connector_id="linux_auth",
        connector_options={"analysis_year": 2025},
        actor="pytest",
    )
    second = application_service.analyze_and_persist_source(
        analysis_name="Linux 2026",
        original_filename="auth.log",
        raw_content=content,
        connector_id="linux_auth",
        connector_options={"analysis_year": 2026},
        actor="pytest",
    )
    duplicate = application_service.analyze_and_persist_source(
        analysis_name="Linux 2026 duplicate",
        original_filename="auth.log",
        raw_content=content,
        connector_id="linux_auth",
        connector_options={"analysis_year": 2026},
        actor="pytest",
    )

    assert first.was_persisted
    assert second.was_persisted
    assert first.session_uuid != second.session_uuid
    assert not duplicate.was_persisted
    assert duplicate.session_uuid == second.session_uuid
    assert pd.to_datetime(first.pipeline.events_df.iloc[0]["timestamp"], utc=True).year == 2025
    assert pd.to_datetime(second.pipeline.events_df.iloc[0]["timestamp"], utc=True).year == 2026

    first_meta = application_service.get_analysis_metadata(first.session_uuid)
    second_meta = application_service.get_analysis_metadata(second.session_uuid)
    assert first_meta["analysis_fingerprint"] != second_meta["analysis_fingerprint"]
    assert first_meta["analysis_context"]["sources"][0]["options"] == {"analysis_year": 2025}
    assert second_meta["analysis_context"]["sources"][0]["options"] == {"analysis_year": 2026}


def test_expired_lockout_resets_failure_window(security_environment) -> None:
    client, factory = security_environment
    with factory() as session:
        user = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert user is not None
        user.failed_login_count = 5
        user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"
    with factory() as session:
        user = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert user is not None
        assert user.failed_login_count == 1
        assert user.locked_until is None


def test_login_does_not_disclose_disabled_or_locked_account_state(security_environment) -> None:
    client, factory = security_environment
    with factory() as session:
        viewer = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "viewer")
        )
        analyst = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert viewer is not None and analyst is not None
        viewer.is_active = False
        analyst.failed_login_count = 5
        analyst.locked_until = datetime.now(UTC) + timedelta(minutes=5)
        session.commit()

    disabled = client.post(
        "/api/v1/auth/login",
        data={"username": "viewer", "password": "ViewerPass!234"},
    )
    locked = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "AnalystPass!234"},
    )
    missing = client.post(
        "/api/v1/auth/login",
        data={"username": "missing-user", "password": "AnyPass!234"},
    )
    for response in (disabled, locked, missing):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"
        assert response.json()["error"]["message"] == "Invalid username or password."


def _incident_details(*, assignee: str | None = "analyst") -> dict[str, Any]:
    return {
        "incident": {
            "incident_uuid": "incident-1",
            "assignee": assignee,
            "status": "open",
            "priority": "P2",
        },
        "alerts": [],
        "events": [],
        "notes": [],
        "evidence": [],
        "audit": [],
        "correlation_entities": [],
        "correlation_relationships": [],
    }


def test_status_only_patch_preserves_existing_assignee_and_priority(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from database.service import ThreatLensPersistenceService

    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "get_incident_details",
        lambda self, incident_uuid: _incident_details(),
    )
    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "update_incident_workflow",
        lambda self, **kwargs: captured.update(kwargs),
    )

    response = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(analyst),
        json={"status": "investigating"},
    )
    assert response.status_code == 200, response.text
    assert captured["assignee"] == "analyst"
    assert captured["priority"] == "P2"
    assert captured["status"] == "investigating"


def test_assignment_target_must_exist_be_active_and_investigator_eligible(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from database.service import ThreatLensPersistenceService

    client, factory = security_environment
    senior = login(client, "senior", "SeniorPass!234")
    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "get_incident_details",
        lambda self, incident_uuid: _incident_details(assignee="analyst"),
    )
    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "update_incident_workflow",
        lambda self, **kwargs: None,
    )

    missing = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(senior),
        json={"assignee": "does-not-exist"},
    )
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "invalid_incident_assignee"

    ineligible = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(senior),
        json={"assignee": "viewer"},
    )
    assert ineligible.status_code == 422
    assert ineligible.json()["error"]["code"] == "ineligible_incident_assignee"

    with factory() as session:
        target = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert target is not None
        target.is_active = False
        session.commit()
    inactive = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(senior),
        json={"assignee": "analyst"},
    )
    # No assignment change is requested when the current assignee is already analyst, so
    # first make the case unassigned to force target validation.
    assert inactive.status_code == 200

    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "get_incident_details",
        lambda self, incident_uuid: _incident_details(assignee=None),
    )
    inactive = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(senior),
        json={"assignee": "analyst"},
    )
    assert inactive.status_code == 422
    assert inactive.json()["error"]["code"] == "invalid_incident_assignee"


def test_invalid_incident_transition_returns_conflict_not_internal_error(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from database.service import ThreatLensPersistenceService

    client, _ = security_environment
    commander = login(client, "commander", "CommanderPass!234")
    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "get_incident_details",
        lambda self, incident_uuid: _incident_details(),
    )

    def fail_update(self, **kwargs):
        raise InvalidIncidentStateError("Transition open -> resolved is not allowed.")

    monkeypatch.setattr(ThreatLensPersistenceService, "update_incident_workflow", fail_update)
    response = client.patch(
        "/api/v1/incidents/incident-1/workflow",
        headers=auth_header(commander),
        json={"status": "resolved"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "workflow_update_failed"


def test_rate_limiter_uses_bounded_cardinality_and_normalized_generic_bucket() -> None:
    first_bucket, first_policy = RateLimitMiddleware._bucket("/api/v1/incidents/abc")
    second_bucket, second_policy = RateLimitMiddleware._bucket("/api/v1/unknown/random/path")
    assert first_bucket == second_bucket == "api-general"
    assert first_policy == second_policy == RateLimitPolicy(requests=300, window_seconds=60)

    limiter = InMemoryRateLimiter(max_keys=32)

    async def exercise() -> None:
        for index in range(200):
            allowed, _, _ = await limiter.allow(
                f"client-{index}:api-general",
                RateLimitPolicy(requests=10, window_seconds=60),
            )
            assert allowed

    asyncio.run(exercise())
    assert len(limiter._events) <= 32
    assert len(limiter._last_seen) <= 32


def test_report_names_are_collision_safe(tmp_path: Path) -> None:
    pipeline = AnalysisPipelineResult(
        events_df=pd.DataFrame(),
        alerts_df=pd.DataFrame(),
        incidents_df=pd.DataFrame(),
        timeline_df=pd.DataFrame(),
    )
    first = Path(
        generate_incident_report(
            pipeline.events_df,
            pipeline.alerts_df,
            pipeline.incidents_df,
            pipeline.timeline_df,
            output_dir=str(tmp_path),
        )
    )
    second = Path(
        generate_incident_report(
            pipeline.events_df,
            pipeline.alerts_df,
            pipeline.incidents_df,
            pipeline.timeline_df,
            output_dir=str(tmp_path),
        )
    )
    assert first != second
    assert first.exists() and second.exists()


def test_report_endpoint_removes_temporary_server_file(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from api.routes import reports as reports_route
    from app.application_service import ThreatLensApplicationService

    client, _ = security_environment
    viewer = login(client, "viewer", "ViewerPass!234")
    pipeline = AnalysisPipelineResult(
        events_df=pd.DataFrame(),
        alerts_df=pd.DataFrame(),
        incidents_df=pd.DataFrame(),
        timeline_df=pd.DataFrame(),
    )
    report_path = tmp_path / "server-report.pdf"
    report_path.write_bytes(b"%PDF-test")

    monkeypatch.setattr(ThreatLensApplicationService, "load_analysis", lambda self, uuid: pipeline)
    monkeypatch.setattr(
        ThreatLensApplicationService,
        "get_analysis_metadata",
        lambda self, uuid: {"name": "Report test"},
    )
    monkeypatch.setattr(
        reports_route,
        "generate_incident_report",
        lambda *args, **kwargs: str(report_path),
    )

    response = client.get(
        "/api/v1/reports/analyses/test-session/incident.pdf",
        headers=auth_header(viewer),
    )
    assert response.status_code == 200
    assert response.content == b"%PDF-test"
    assert not report_path.exists()


def test_upload_route_offloads_analysis_to_threadpool(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from api.routes import analyses as analyses_route
    from app.application_service import ThreatLensApplicationService

    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    called = {"threadpool": False}

    async def fake_threadpool(callable_obj):
        called["threadpool"] = True
        return callable_obj()

    pipeline = AnalysisPipelineResult(
        events_df=pd.DataFrame(),
        alerts_df=pd.DataFrame(),
        incidents_df=pd.DataFrame(),
        timeline_df=pd.DataFrame(),
    )
    result = AnalysisExecutionResult(
        pipeline=pipeline,
        persistence=None,
        duplicate_session_uuid=None,
    )
    monkeypatch.setattr(analyses_route, "run_in_threadpool", fake_threadpool)
    monkeypatch.setattr(
        ThreatLensApplicationService,
        "analyze_and_persist_source",
        lambda self, **kwargs: result,
    )

    response = client.post(
        "/api/v1/analyses/upload",
        headers=auth_header(analyst),
        data={"analysis_name": "Threadpool test"},
        files=[("files", ("auth.log", b"sample telemetry"))],
    )
    assert response.status_code == 201, response.text
    assert called["threadpool"]


def test_release_runtime_dependencies_are_exactly_pinned() -> None:
    for filename in ("requirements.txt", "requirements-dev.txt"):
        for line in Path(filename).read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assert "==" in stripped, f"Unpinned release dependency in {filename}: {stripped}"


def test_current_ui_has_no_personal_default_or_stale_detection_milestone() -> None:
    state_source = Path("app/state.py").read_text(encoding="utf-8")
    quality_source = Path("app/pages/detection_quality.py").read_text(encoding="utf-8")
    assert '"analyst_identity": "saketh"' not in state_source
    assert "v0.6 detection catalogue" not in quality_source
    assert "threatlens_v0.6_detection_quality.csv" not in quality_source


def test_legacy_mitre_mapper_is_explicitly_deprecated_and_not_imported_by_production() -> None:
    mapper = Path("core/mitre_mapper.py").read_text(encoding="utf-8")
    assert "Deprecated compatibility mappings" in mapper
    production_roots = (
        Path("api"),
        Path("app"),
        Path("attack"),
        Path("correlation"),
        Path("database"),
    )
    imported_by = []
    for root in production_roots:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "core.mitre_mapper" in text:
                imported_by.append(path.as_posix())
    assert imported_by == []


def test_repository_hygiene_rejects_any_tracked_zip() -> None:
    from scripts.verify_repository_hygiene import _forbidden_tracked

    assert _forbidden_tracked("ThreatLensAI_v0.9.2_FINAL.zip")
    assert _forbidden_tracked("vendor/random.zip")
