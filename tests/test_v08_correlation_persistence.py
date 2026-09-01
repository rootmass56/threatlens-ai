
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.pipeline import SourceInput, analyze_sources
from database.base import Base
from database.models import (
    AttackGraphSnapshotModel,
    CorrelationEntityModel,
    CorrelationRelationshipModel,
    CorrelationRunModel,
    IncidentModel,
)
from database.service import ThreatLensPersistenceService

SAMPLE_DIR = Path("data/sample_logs")


def _pipeline():
    names = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    return analyze_sources(
        [
            SourceInput(
                raw_content=(SAMPLE_DIR / name).read_bytes(),
                filename=name,
            )
            for name in names
        ]
    )


def test_advanced_correlation_and_graph_are_persisted_transactionally():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        pipeline = _pipeline()
        service = ThreatLensPersistenceService(session)
        result = service.persist_analysis(
            analysis_name="v0.8 persistence test",
            source_type="multi_source",
            original_filename="multi-source-demo",
            raw_content=b"v0.8-correlation-persistence",
            events_df=pipeline.events_df,
            alerts_df=pipeline.alerts_df,
            incidents_df=pipeline.incidents_df,
            correlation_result=pipeline.correlation_result,
            actor="pytest",
        )
        session.commit()

        assert session.scalar(select(func.count(CorrelationRunModel.id))) == 1
        assert session.scalar(select(func.count(CorrelationEntityModel.id))) >= 8
        assert session.scalar(select(func.count(CorrelationRelationshipModel.id))) >= 10
        assert session.scalar(select(func.count(AttackGraphSnapshotModel.id))) == 1
        assert session.scalar(select(func.count(IncidentModel.id))) == 2

        details = service.get_analysis_details(result.session_uuid)
        assert details is not None
        correlation = details["correlation"]
        assert correlation["version"] == "0.8.0"
        assert correlation["metrics"]["deduplicated_alerts"] == 1
        assert len(correlation["graph"]["nodes"]) > 0
        assert len(correlation["graph_sha256"]) == 64
        assert all(item["correlation_id"] for item in details["incidents"])
        assert all(item["graph_score"] > 0 for item in details["incidents"])

        incident_uuid = details["incidents"][0]["incident_uuid"]
        incident_details = service.get_incident_details(incident_uuid)
        assert incident_details is not None
        assert incident_details["correlation_entities"]
        assert incident_details["correlation_relationships"]
        assert incident_details["incident"]["storyline"]
    finally:
        session.close()
        engine.dispose()
