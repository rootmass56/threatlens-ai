
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.pipeline import analyze_linux_auth_log
from database.base import Base
from database.models import AlertModel, AnalysisSessionModel, EventModel
from database.service import ThreatLensPersistenceService

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def test_common_schema_parser_and_rule_metadata_are_persisted():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        raw = SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")
        pipeline = analyze_linux_auth_log(raw)
        statistics = pipeline.parser_result.statistics.model_dump(mode="json")
        result = ThreatLensPersistenceService(session).persist_analysis(
            analysis_name="v0.4 metadata test",
            source_type="linux_auth",
            connector_id="linux_auth",
            schema_version="1.0.0",
            rule_catalog_version="0.4.0",
            original_filename=SAMPLE_LOG_PATH.name,
            raw_content=raw,
            events_df=pipeline.events_df,
            alerts_df=pipeline.alerts_df,
            incidents_df=pipeline.incidents_df,
            parser_statistics=statistics,
            actor="pytest",
        )
        session.commit()
        analysis = session.scalars(select(AnalysisSessionModel)).one()
        event = session.scalars(select(EventModel).order_by(EventModel.id)).first()
        alert = session.scalars(select(AlertModel).order_by(AlertModel.id)).first()
        assert result.parse_success_rate == 1.0
        assert analysis.connector_id == "linux_auth"
        assert analysis.schema_version == "1.0.0"
        assert analysis.rule_catalog_version == "0.4.0"
        assert analysis.parser_statistics_json["parsed_records"] == 9
        assert event and event.source_product == "linux"
        assert event.parser_version == "1.0.0"
        assert event.data_quality_json
        assert alert and alert.rule_id
        assert alert.rule_status == "stable"
        assert alert.risk_factors_json
    finally:
        session.close()
        engine.dispose()
