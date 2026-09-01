
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_service import ThreatLensApplicationService
from database.base import Base

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


@pytest.fixture
def application_service():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    @contextmanager
    def test_session_scope():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    service = ThreatLensApplicationService(session_context_factory=test_session_scope)
    try:
        yield service
    finally:
        engine.dispose()


def test_application_service_persists_and_reloads_analysis(application_service):
    log_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
    result = application_service.analyze_and_persist_linux_log(
        analysis_name="Application service test",
        original_filename="auth_sample.log",
        log_text=log_text,
        raw_content=log_text,
        actor="pytest",
    )
    assert result.was_persisted
    assert result.session_uuid is not None
    assert result.pipeline.event_count == 9
    assert result.pipeline.alert_count == 4
    assert result.pipeline.incident_count == 1
    reloaded = application_service.load_analysis(result.session_uuid)
    assert reloaded is not None
    assert reloaded.event_count == 9
    assert reloaded.alert_count == 4
    assert reloaded.incident_count == 1
    metadata = application_service.get_analysis_metadata(result.session_uuid)
    assert metadata is not None
    assert metadata["name"] == "Application service test"


def test_application_service_detects_duplicate(application_service):
    log_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
    first = application_service.analyze_and_persist_linux_log(
        analysis_name="Original analysis",
        original_filename="auth_sample.log",
        log_text=log_text,
        raw_content=log_text,
        actor="pytest",
    )
    duplicate = application_service.analyze_and_persist_linux_log(
        analysis_name="Duplicate analysis",
        original_filename="auth_sample.log",
        log_text=log_text,
        raw_content=log_text,
        actor="pytest",
    )
    assert first.was_persisted
    assert not duplicate.was_persisted
    assert duplicate.duplicate_session_uuid == first.session_uuid
    assert duplicate.session_uuid == first.session_uuid
    assert duplicate.pipeline.incident_count == 1
    assert duplicate.pipeline.incidents_df["incident_uuid"].notna().all()
    assert duplicate.pipeline.incidents_df["priority"].eq("P1").all()
    assert duplicate.pipeline.connector_ids == first.pipeline.connector_ids
    assert duplicate.pipeline.parse_success_rate == first.pipeline.parse_success_rate
    assert len(application_service.get_analysis_history()) == 1


def test_persistent_metrics_and_audit_are_calculated(application_service):
    log_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
    result = application_service.analyze_and_persist_linux_log(
        analysis_name="Metrics test",
        original_filename="auth_sample.log",
        log_text=log_text,
        raw_content=log_text,
        actor="pytest",
    )
    metrics = application_service.get_persistent_metrics()
    assert metrics["total_analyses"] == 1
    assert metrics["total_events"] == 9
    assert metrics["total_alerts"] == 4
    assert metrics["total_incidents"] == 1
    assert metrics["open_incidents"] == 1
    audit = application_service.get_audit_logs(entity_id=result.session_uuid)
    assert len(audit) == 1


def test_application_service_persists_multi_source_analysis(application_service):
    from core.pipeline import SourceInput

    sample_dir = Path("data/sample_logs")
    filenames = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    sources = [
        SourceInput(raw_content=(sample_dir / name).read_bytes(), filename=name)
        for name in filenames
    ]
    result = application_service.analyze_and_persist_sources(
        analysis_name="Multi-source application service test",
        sources=sources,
        actor="pytest",
    )
    assert result.was_persisted
    assert result.pipeline.event_count == 22
    assert result.pipeline.alert_count == 7
    assert result.pipeline.incident_count == 2
    assert result.pipeline.quarantined_count == 0
    metadata = application_service.get_analysis_metadata(result.session_uuid)
    assert metadata is not None
    assert metadata["connector_id"] == "multi_source"
    assert metadata["rule_catalog_version"] == "0.7.0"


def test_duplicate_multi_source_analysis_preserves_diagnostics_and_case_metadata(
    application_service,
):
    from core.pipeline import SourceInput

    sample_dir = Path("data/sample_logs")
    filenames = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    sources = [
        SourceInput(raw_content=(sample_dir / name).read_bytes(), filename=name)
        for name in filenames
    ]

    first = application_service.analyze_and_persist_sources(
        analysis_name="Original multi-source analysis",
        sources=sources,
        actor="pytest",
    )
    duplicate = application_service.analyze_and_persist_sources(
        analysis_name="Duplicate multi-source analysis",
        sources=sources,
        actor="pytest",
    )

    assert first.was_persisted
    assert not duplicate.was_persisted
    assert duplicate.session_uuid == first.session_uuid
    assert duplicate.pipeline.event_count == 22
    assert duplicate.pipeline.alert_count == 7
    assert duplicate.pipeline.incident_count == 2
    assert len(duplicate.pipeline.all_parser_results) == 5
    assert duplicate.pipeline.connector_ids == (
        "windows_security",
        "windows_sysmon",
        "suricata_eve",
        "zeek",
    )
    assert duplicate.pipeline.parse_success_rate == 1.0
    assert duplicate.pipeline.incidents_df["incident_uuid"].notna().all()
    assert duplicate.pipeline.incidents_df["priority"].eq("P1").all()
