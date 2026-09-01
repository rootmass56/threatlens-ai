
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pandas as pd
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.rbac import ROLE_DEFINITIONS
from api.routes.analyses import _pipeline_payload
from app.application_service import ThreatLensApplicationService
from app.case_policy import case_capabilities
from app.upload_limits import MIB, enforce_file_size, streamlit_upload_limit_mb
from core.pipeline import SourceInput
from core.report_generator import additional_analysis_event_records, build_case_timeline_records
from database.base import Base
from database.models import AnalysisSessionModel, AuditLogModel
from tests.test_persistence_service import persist_sample_analysis


@pytest.fixture
def database_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _viewer() -> dict:
    role = ROLE_DEFINITIONS["viewer"]
    return {"username": "viewer", "permissions": sorted(role.permissions)}


def _analyst() -> dict:
    role = ROLE_DEFINITIONS["analyst"]
    return {"username": "analyst", "permissions": sorted(role.permissions)}


def test_noop_workflow_does_not_create_audit_record(database_session) -> None:
    service, _, _ = persist_sample_analysis(database_session)
    incident_uuid = service.list_incident_cases()[0]["incident_uuid"]
    service.update_incident_workflow(
        incident_uuid=incident_uuid,
        status="investigating",
        assignee="analyst",
        priority="P1",
        actor="admin",
    )
    database_session.flush()
    before = database_session.scalar(select(func.count(AuditLogModel.id)))

    service.update_incident_workflow(
        incident_uuid=incident_uuid,
        status="investigating",
        assignee="analyst",
        priority="P1",
        actor="admin",
    )
    database_session.flush()
    after = database_session.scalar(select(func.count(AuditLogModel.id)))

    assert after == before


def test_real_workflow_change_still_creates_one_audit_record(database_session) -> None:
    service, _, _ = persist_sample_analysis(database_session)
    incident_uuid = service.list_incident_cases()[0]["incident_uuid"]
    before = database_session.scalar(select(func.count(AuditLogModel.id)))
    service.update_incident_workflow(
        incident_uuid=incident_uuid,
        status="investigating",
        assignee=None,
        priority="P2",
        actor="admin",
    )
    database_session.flush()
    after = database_session.scalar(select(func.count(AuditLogModel.id)))
    assert after == before + 1


def test_evidence_details_expose_registered_actor_from_audit(database_session) -> None:
    service, _, _ = persist_sample_analysis(database_session)
    incident_uuid = service.list_incident_cases()[0]["incident_uuid"]
    evidence_uuid = service.register_evidence(
        incident_uuid=incident_uuid,
        evidence_type="log_file",
        description="Evidence actor provenance",
        source_reference="data/sample_logs/auth_sample.log",
        sha256="a" * 64,
        actor="analyst",
    )
    database_session.flush()
    details = service.get_incident_details(incident_uuid)
    assert details is not None
    evidence = next(item for item in details["evidence"] if item["evidence_uuid"] == evidence_uuid)
    assert evidence["registered_by"] == "analyst"


def test_case_timeline_is_incident_linked_and_additional_events_are_separate() -> None:
    details = {
        "events": [
            {
                "event_uuid": "linked",
                "timestamp": "2026-01-01T00:00:01Z",
                "source_ip": "10.0.0.1",
                "username": "alice",
                "normalized_message": "linked event",
            }
        ],
        "alerts": [
            {
                "timestamp": "2026-01-01T00:00:02Z",
                "severity": "High",
                "description": "linked alert",
                "source_ip": "10.0.0.1",
                "username": "alice",
            }
        ],
    }
    case_timeline = build_case_timeline_records(details)
    assert [item["type"] for item in case_timeline] == ["Event", "Alert"]
    assert all("unlinked" not in item["description"] for item in case_timeline)

    analysis_events = pd.DataFrame(
        [
            {"event_uuid": "linked", "timestamp": "2026-01-01T00:00:01Z", "raw_message": "linked"},
            {
                "event_uuid": "unlinked",
                "timestamp": "2026-01-01T00:10:00Z",
                "raw_message": "unlinked",
            },
        ]
    )
    additional = additional_analysis_event_records(analysis_events, [details])
    assert [item["event_uuid"] for item in additional] == ["unlinked"]

    report_source = Path("core/report_generator.py").read_text(encoding="utf-8")
    assert "KeepTogether" in report_source
    assert "recommendation_flowables" in report_source
    assert "story.append(KeepTogether(recommendation_flowables))" in report_source


def test_openapi_declares_pdf_response_as_application_pdf(monkeypatch) -> None:
    monkeypatch.setenv(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api.main import create_app

    operation = create_app().openapi()["paths"][
        "/api/v1/reports/analyses/{session_uuid}/incident.pdf"
    ]["get"]
    content = operation["responses"]["200"]["content"]
    assert "application/pdf" in content
    assert "application/json" not in content
    assert content["application/pdf"]["schema"] == {"type": "string", "format": "binary"}


def test_multisource_demo_preserves_user_analysis_name() -> None:
    source = Path("app/pages/upload.py").read_text(encoding="utf-8")
    assert 'analysis_name=analysis_name.strip() or "ThreatLens Multi-Source Demo"' in source
    assert 'analysis_name="ThreatLens Multi-Source Demo"' not in source


def test_viewer_case_capabilities_are_read_only() -> None:
    caps = case_capabilities(
        _viewer(),
        {"status": "investigating", "assignee": "analyst"},
    )
    assert not caps.can_update
    assert not caps.can_add_note
    assert not caps.can_add_evidence
    assert not caps.can_assign_any


def test_analyst_can_modify_self_assigned_case_but_not_another_analysts_case() -> None:
    self_caps = case_capabilities(_analyst(), {"status": "investigating", "assignee": "analyst"})
    other_caps = case_capabilities(_analyst(), {"status": "investigating", "assignee": "other"})
    assert self_caps.can_update and self_caps.can_add_note and self_caps.can_add_evidence
    assert not other_caps.can_update
    assert not other_caps.can_add_note
    assert not other_caps.can_add_evidence


def test_analyst_ui_does_not_offer_close_or_false_positive_transitions() -> None:
    caps = case_capabilities(_analyst(), {"status": "investigating", "assignee": "analyst"})
    assert "contained" in caps.status_options
    assert "resolved" not in caps.status_options
    assert "false_positive" not in caps.status_options


def test_case_details_ui_renders_read_only_paths_and_synchronizes_case_analysis_state() -> None:
    source = Path("app/pages/case_details.py").read_text(encoding="utf-8")
    assert 'key="selected_incident_uuid"' in source
    assert "store_loaded_analysis(" in source
    assert "Read-only workflow access" in source
    assert "Read-only evidence access" in source
    assert "Read-only note access" in source
    assert "No changes detected. Case workflow was not modified" in source
    assert "Case workflow updated and audited when state changed." not in source


def test_clear_current_analysis_also_clears_active_case_state() -> None:
    source = Path("app/state.py").read_text(encoding="utf-8")
    clear_block = source[source.index("def clear_current_analysis") :]
    assert '"selected_incident_uuid"' in clear_block


def test_stale_per_rule_catalog_version_metadata_is_removed() -> None:
    stale = []
    for path in Path("rules").rglob("*.yml"):
        if "catalog_version:" in path.read_text(encoding="utf-8"):
            stale.append(path.as_posix())
    assert stale == []


def test_rule_source_provenance_is_repository_relative() -> None:
    service = ThreatLensApplicationService()
    catalog = service.get_rule_catalog()
    assert not catalog.empty
    for source_path in catalog["source_path"].dropna().astype(str):
        path = Path(source_path)
        assert not path.is_absolute()
        assert source_path.replace("\\", "/").startswith("rules/")


def test_browser_upload_limit_helpers_enforce_authoritative_byte_boundary() -> None:
    assert streamlit_upload_limit_mb(10 * MIB) == 11
    assert streamlit_upload_limit_mb(512 * 1024) == 1
    enforce_file_size(10 * MIB, 10 * MIB, label="evidence.log")
    try:
        enforce_file_size(10 * MIB + 1, 10 * MIB, label="evidence.log")
    except ValueError as error:
        assert "10.0 MiB" in str(error)
    else:
        raise AssertionError("oversized evidence file was not rejected")


def test_file_upload_widgets_use_authoritative_per_widget_caps() -> None:
    upload_source = Path("app/pages/upload.py").read_text(encoding="utf-8")
    case_source = Path("app/pages/case_details.py").read_text(encoding="utf-8")
    helper_assignment = "widget_limit_mb = streamlit_upload_limit_mb(max_file_bytes)"
    assert helper_assignment in upload_source
    assert helper_assignment in case_source
    assert "max_upload_size=widget_limit_mb" in upload_source
    assert "max_upload_size=widget_limit_mb" in case_source
    assert "Streamlit uses " in upload_source and "decimal MB" in upload_source
    assert "Streamlit uses " in case_source and "decimal MB" in case_source
    assert "ThreatLens still enforces the exact " in upload_source
    assert "MiB API limit" in upload_source
    assert "exact API byte limit" in case_source
    assert "enforce_file_size(" in case_source


def test_hard_refresh_reauthentication_policy_is_documented() -> None:
    source = Path("app/auth_ui.py").read_text(encoding="utf-8")
    assert "hard browser refresh" in source.lower()
    assert "not persisted to browser localStorage or cookies" in source
    assert "localStorage.setItem" not in source
    assert "document.cookie" not in source


def test_persisted_multisource_reload_rehydrates_current_workspace_context(
    database_session,
) -> None:
    @contextmanager
    def session_scope():
        try:
            yield database_session
            database_session.commit()
        except Exception:
            database_session.rollback()
            raise

    service = ThreatLensApplicationService(session_context_factory=session_scope)
    sample_dir = Path("data/sample_logs")
    filenames = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    result = service.analyze_and_persist_sources(
        analysis_name="Persisted reload UAT",
        sources=[
            SourceInput(raw_content=(sample_dir / name).read_bytes(), filename=name)
            for name in filenames
        ],
        actor="pytest",
    )
    assert result.session_uuid is not None

    persisted = database_session.scalar(
        select(AnalysisSessionModel).where(AnalysisSessionModel.session_uuid == result.session_uuid)
    )
    assert persisted is not None

    # Emulate a session produced earlier in v0.9.5, before rule-count persistence was
    # added. The effective rule hash still allows the exact count to be proven.
    context = dict(persisted.analysis_context_json or {})
    context.pop("loaded_rule_count", None)
    persisted.analysis_context_json = context
    database_session.commit()

    pipeline = service.load_analysis(result.session_uuid)
    metadata = service.get_analysis_metadata(result.session_uuid)
    assert pipeline is not None and metadata is not None
    payload = _pipeline_payload(pipeline, persisted_metadata=metadata)

    assert len(payload["source_manifest"]) == 5
    assert payload["parser_statistics"]["source_count"] == 5
    assert payload["connector_ids"] == [
        "windows_security",
        "windows_sysmon",
        "suricata_eve",
        "zeek",
    ]
    assert payload["loaded_rule_count"] == 46
    assert len(payload["events"]) == 22
    assert len(payload["alerts"]) == 7
    assert len(payload["incidents"]) == 2
    assert {item["ingest_source"] for item in payload["events"]} == set(filenames)
    assert {item["connector_id"] for item in payload["events"]} == {
        "windows_security",
        "windows_sysmon",
        "suricata_eve",
        "zeek",
    }
