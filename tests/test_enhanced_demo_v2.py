from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.pipeline import analyze_sources
from core.rules.engine import _match_expression
from database.base import Base
from database.models import (
    AnalysisSessionModel,
    EvidenceCustodyEventModel,
    EvidenceModel,
    HuntExecutionModel,
    IncidentModel,
    RagInvestigationQueryModel,
    ResponseExecutionModel,
    SavedHuntModel,
    ThreatIntelHitModel,
)
from scripts.enhanced_demo_v2 import (
    EXPECTED,
    EXPECTED_DETECTIONS,
    build_sources,
    seed,
    validate_pipeline,
)


def test_numeric_rule_equality_survives_nullable_dataframe_float_coercion() -> None:
    assert _match_expression(3389.0, "equals", 3389)
    assert not _match_expression(3389.0, "not_equals", 3389)
    assert not _match_expression(True, "equals", 1)


def test_enhanced_v2_pipeline_contract_is_exact_and_explainable() -> None:
    result = analyze_sources(build_sources())
    assert validate_pipeline(result) == EXPECTED
    assert result.parse_success_rate == 1.0
    assert [item["event_count"] for item in result.source_manifest] == [4, 12, 6, 4, 3]
    assert set(result.alerts_df["detection_name"]) == EXPECTED_DETECTIONS
    assert set(result.alerts_df["mitre_tactic"]) == {
        "Command and Control",
        "Credential Access",
        "Defense Evasion",
        "Defense Impairment",
        "Execution",
        "Lateral Movement",
        "Persistence",
        "Privilege Escalation",
    }
    assert set(result.incidents_df["severity"]) == {"Critical"}
    assert set(result.incidents_df["risk_score"]) == {100}
    assert result.correlation_result is not None
    assert result.correlation_result.metrics == {
        "input_alerts": 26,
        "representative_alerts": 23,
        "deduplicated_alerts": 3,
        "duplicate_groups": 3,
        "entities": 21,
        "relationships": 139,
        "cluster_relationships": 86,
        "incidents": 2,
        "graph_nodes": 76,
        "graph_edges": 300,
        "multi_source_incidents": 2,
        "multi_stage_incidents": 2,
    }


def test_enhanced_v2_seed_is_idempotent_and_namespaced() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    @contextmanager
    def scope():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    first = seed(session_context_factory=scope, include_rag=False)
    second = seed(session_context_factory=scope, include_rag=False)
    assert first == second
    assert first["status"] == "PASS"
    assert first["context"]["events"] == 29
    assert first["context"]["alerts"] == 26
    assert first["context"]["incidents"] == 2
    assert first["context"]["quarantined"] == 0
    assert first["context"]["rag_queries"] == 0

    with scope() as db:
        assert db.scalar(select(func.count(AnalysisSessionModel.id))) == 1
        assert db.scalar(select(func.count(IncidentModel.id))) == 2
        assert db.scalar(select(func.count(EvidenceModel.id))) == 1
        assert db.scalar(select(func.count(EvidenceCustodyEventModel.id))) == 1
        assert db.scalar(select(func.count(SavedHuntModel.id))) == 1
        assert db.scalar(select(func.count(HuntExecutionModel.id))) == 1
        assert db.scalar(select(func.count(ResponseExecutionModel.id))) == 1
        assert db.scalar(select(func.count(RagInvestigationQueryModel.id))) == 0
        assert db.scalar(select(func.count(ThreatIntelHitModel.id))) >= 5
    engine.dispose()
