
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.pipeline import analyze_linux_auth_log
from database.base import Base
from database.exceptions import DuplicateAnalysisError, InvalidIncidentStateError
from database.models import (
    AlertModel,
    AnalysisSessionModel,
    AuditLogModel,
    EventModel,
    EvidenceModel,
    IncidentModel,
    InvestigationNoteModel,
    alert_events,
)
from database.service import ThreatLensPersistenceService

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


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


def persist_sample_analysis(database_session):
    log_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
    pipeline = analyze_linux_auth_log(log_text)
    service = ThreatLensPersistenceService(database_session)
    result = service.persist_analysis(
        analysis_name="Persistence integration test",
        source_type="linux_auth",
        original_filename="auth_sample.log",
        raw_content=log_text,
        events_df=pipeline.events_df,
        alerts_df=pipeline.alerts_df,
        incidents_df=pipeline.incidents_df,
        actor="pytest",
    )
    database_session.commit()
    return service, result, pipeline


def test_complete_analysis_and_explicit_relationships_are_persisted(database_session):
    service, result, _ = persist_sample_analysis(database_session)
    assert result.event_count == 9
    assert result.alert_count == 4
    assert result.incident_count == 1
    assert database_session.scalar(select(func.count(EventModel.id))) == 9
    assert database_session.scalar(select(func.count(AlertModel.id))) == 4
    assert database_session.scalar(select(func.count(IncidentModel.id))) == 1
    assert database_session.scalar(select(func.count(AnalysisSessionModel.id))) == 1
    assert database_session.scalar(select(func.count()).select_from(alert_events)) >= 4
    incident = database_session.scalars(select(IncidentModel)).one()
    assert len(incident.alerts) == 4
    details = service.get_analysis_details(result.session_uuid)
    assert details is not None
    assert len(details["events"]) == 9
    assert len(details["alerts"]) == 4
    assert len(details["incidents"]) == 1
    alert = details["alerts"][0]
    assert len(alert["supporting_event_uuids"]) >= 1
    assert alert["detection_id"]
    assert alert["primary_tactic"] == alert["mitre_tactic"]
    assert alert["primary_technique_id"] == alert["mitre_technique_id"]


def test_duplicate_analysis_is_rejected(database_session):
    service, result, pipeline = persist_sample_analysis(database_session)
    log_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
    with pytest.raises(DuplicateAnalysisError) as error:
        service.persist_analysis(
            analysis_name="Duplicate test",
            source_type="linux_auth",
            original_filename="auth_sample.log",
            raw_content=log_text,
            events_df=pipeline.events_df,
            alerts_df=pipeline.alerts_df,
            incidents_df=pipeline.incidents_df,
            actor="pytest",
        )
    assert error.value.existing_session_uuid == result.session_uuid


def test_incident_state_machine_notes_evidence_and_audit(database_session):
    service, _, _ = persist_sample_analysis(database_session)
    cases = service.list_incident_cases()
    assert len(cases) == 1
    incident_uuid = cases[0]["incident_uuid"]

    with pytest.raises(InvalidIncidentStateError):
        service.update_incident_workflow(
            incident_uuid=incident_uuid,
            status="resolved",
            assignee="saketh",
            priority="P1",
            actor="saketh",
        )

    service.update_incident_workflow(
        incident_uuid=incident_uuid,
        status="investigating",
        assignee="saketh",
        priority="P1",
        actor="saketh",
    )
    note_id = service.add_investigation_note(
        incident_uuid=incident_uuid,
        author="saketh",
        note="Validated the authentication and privilege-escalation sequence.",
    )
    evidence_uuid = service.register_evidence(
        incident_uuid=incident_uuid,
        evidence_type="log_file",
        description="Original Linux authentication log",
        source_reference=str(SAMPLE_LOG_PATH),
        sha256="a" * 64,
        actor="saketh",
    )
    database_session.commit()

    details = service.get_incident_details(incident_uuid)
    assert details is not None
    assert details["incident"]["status"] == "investigating"
    assert details["incident"]["assignee"] == "saketh"
    assert len(details["alerts"]) == 4
    assert len(details["events"]) >= 6
    assert note_id and evidence_uuid
    assert database_session.scalar(select(func.count(InvestigationNoteModel.id))) == 1
    assert database_session.scalar(select(func.count(EvidenceModel.id))) == 1
    assert database_session.scalar(select(func.count(AuditLogModel.id))) >= 4
