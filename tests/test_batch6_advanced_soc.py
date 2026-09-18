from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("THREATLENS_JWT_SECRET", "batch6-test-secret-that-is-long-enough-123456789")

from advanced_soc.schemas import (
    CaseProfileUpdate,
    CustodyEventCreate,
    DetectionFeedbackCreate,
    DetectionTuningCreate,
    DetectionTuningReview,
    GraphPathRequest,
    HuntQuery,
    IncidentTaskCreate,
    IngestionSourceCreate,
    PlaybookApprovalRequest,
    PlaybookExecutionComplete,
    PlaybookExecutionRequest,
    ThreatFeedCreate,
    ThreatIndicatorInput,
    ThreatIntelImportRequest,
)
from advanced_soc.service import AdvancedSocService
from api.config import SecuritySettings
from api.main import create_app
from api.version import THREATLENS_VERSION
from app.application_service import ThreatLensApplicationService
from core.connectors import build_default_connector_registry
from core.rules.fixtures import RuleFixtureRunner
from core.rules.loader import RuleLoader
from database.base import Base
from database.models import AlertModel, EvidenceModel, IncidentModel

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def batch6_environment():
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

    app_service = ThreatLensApplicationService(session_context_factory=scope)
    raw = (ROOT / "data" / "sample_logs" / "auth_sample.log").read_text(encoding="utf-8")
    result = app_service.analyze_and_persist_linux_log(
        analysis_name="Batch 6 regression",
        original_filename="auth_sample.log",
        log_text=raw,
        raw_content=raw,
        actor="pytest",
    )
    try:
        yield scope, result
    finally:
        engine.dispose()


def test_batch6_version_connectors_and_governed_rule_matrix() -> None:
    assert THREATLENS_VERSION == "0.14.0"
    assert build_default_connector_registry().connector_ids() == [
        "entra_id",
        "linux_auth",
        "suricata_eve",
        "syslog_rfc",
        "windows_security",
        "windows_sysmon",
        "zeek",
    ]
    catalog = RuleLoader(ROOT / "rules").validation_report()
    assert catalog.valid, [issue.message for issue in catalog.issues]
    assert len(catalog.rules) == 46
    fixture_report = RuleFixtureRunner(ROOT / "rules").run()
    assert fixture_report.passed
    assert fixture_report.passed_count == 138


def test_entra_connector_normalizes_batch6_identity_security_events() -> None:
    registry = build_default_connector_registry()
    connector = registry.get("entra_id")
    cases = {
        "entra_mfa_failure": "entra_mfa_failure",
        "entra_risky_signin": "entra_risky_signin",
        "entra_signin_failure": "entra_signin_failure",
        "entra_privileged_role_assignment": "entra_privileged_role_assignment",
    }
    for fixture_dir, expected_type in cases.items():
        source = (ROOT / "rules" / "fixtures" / fixture_dir / "positive.jsonl").read_bytes()
        parsed = connector.parse(source, filename=f"{fixture_dir}.jsonl")
        assert len(parsed.events) == 1
        assert parsed.events[0].source_category == "identity"
        assert parsed.events[0].event_type == expected_type
        assert parsed.statistics.parse_success_rate == 1.0


def test_advanced_soc_service_end_to_end_governance(batch6_environment) -> None:
    scope, analysis = batch6_environment
    with scope() as session:
        service = AdvancedSocService(session)
        incident = session.scalar(select(IncidentModel))
        alert = session.scalar(select(AlertModel))
        assert incident is not None and alert is not None

        evidence = EvidenceModel(
            evidence_uuid="00000000-0000-0000-0000-000000000006",
            incident_id=incident.id,
            evidence_type="log",
            description="Batch 6 chain-of-custody regression evidence",
        )
        session.add(evidence)
        session.flush()

        feed = service.create_feed(
            ThreatFeedCreate(
                name="Batch 6 test intelligence",
                provider="ThreatLens Test",
                feed_format="curated_json",
                tlp="TLP:CLEAR",
                default_confidence=80,
                metadata={"purpose": "regression"},
            ),
            "admin",
        )
        imported = service.import_indicators(
            feed["feed_uuid"],
            ThreatIntelImportRequest(
                indicators=[
                    ThreatIndicatorInput(
                        indicator_type="ipv4",
                        value="203.0.113.50",
                        confidence=95,
                        tlp="TLP:CLEAR",
                        malicious_score=0.95,
                        tags=["batch6"],
                    )
                ]
            ),
            "admin",
        )
        assert imported["added"] == 1

        enrichment = service.enrich_analysis(analysis.session_uuid, "admin")
        assert enrichment["new_hits"] >= 1
        assert enrichment["authority"] == "external_intelligence_enrichment_only"

        hunt = service.execute_hunt(
            HuntQuery(query="203.0.113.50", limit=50, offset=0, sort="desc"),
            "analyst",
        )
        assert hunt["total"] >= 5
        assert hunt["returned"] >= 5

        profile = service.update_case_profile(
            incident.incident_uuid,
            CaseProfileUpdate(
                team="Tier-2 SOC",
                escalation_level=1,
                disposition="true_positive",
                containment_status="in_progress",
                watchers=["admin"],
                tags=["identity", "batch6"],
            ),
            "admin",
        )
        assert profile["team"] == "Tier-2 SOC"

        task = service.create_task(
            incident.incident_uuid,
            IncidentTaskCreate(
                task_type="investigation",
                title="Validate compromised identity",
                description="Correlate authentication, endpoint and network evidence.",
                priority="P2",
                assignee="analyst",
                approval_required=False,
            ),
            "admin",
        )
        assert task["status"] == "open"

        custody = service.add_custody_event(
            evidence.evidence_uuid,
            CustodyEventCreate(
                action="transferred",
                from_custodian="SOC",
                to_custodian="IR",
                location="Evidence vault",
                notes="Hash checked before transfer.",
                hash_verified=True,
            ),
            "admin",
        )
        assert custody["hash_verified"] is True

        service.ensure_default_playbooks()
        playbooks = service.list_playbooks()
        assert len(playbooks) >= 3
        requested = service.request_playbook(
            incident.incident_uuid,
            PlaybookExecutionRequest(
                playbook_uuid=playbooks[0]["playbook_uuid"],
                parameters={"mode": "simulation"},
            ),
            "analyst",
        )
        assert requested["status"] == "requested"
        with pytest.raises(PermissionError, match="requester cannot approve"):
            service.approve_execution(
                requested["execution_uuid"],
                PlaybookApprovalRequest(approved=True, note="Self-approval must fail."),
                "analyst",
            )
        approved = service.approve_execution(
            requested["execution_uuid"],
            PlaybookApprovalRequest(approved=True, note="Evidence validated."),
            "incident_commander",
        )
        assert approved["status"] == "approved"
        completed = service.complete_execution(
            requested["execution_uuid"],
            PlaybookExecutionComplete(
                outcome="success",
                result={"simulated": True},
                rollback_notes="No production-side mutation was performed.",
            ),
            "senior_analyst",
        )
        assert completed["status"] == "completed"
        assert completed["result"]["reported_result"]["simulated"] is True

        feedback = service.create_detection_feedback(
            DetectionFeedbackCreate(
                alert_uuid=alert.alert_uuid,
                incident_uuid=incident.incident_uuid,
                verdict="true_positive",
                reason="Confirmed by analyst evidence review.",
            ),
            "analyst",
        )
        assert feedback["verdict"] == "true_positive"

        tuning = service.propose_tuning(
            DetectionTuningCreate(
                rule_id=alert.rule_id or alert.detection_id,
                rule_version="1",
                proposal_type="threshold",
                proposal={"count": 6},
                rationale="Governed proposal; do not mutate runtime rules silently.",
            ),
            "rule_engineer",
        )
        reviewed = service.review_tuning(
            tuning["tuning_uuid"],
            DetectionTuningReview(decision="approved", review_note="Proceed through YAML + fixtures."),
            "rule_engineer",
        )
        assert reviewed["status"] == "approved"
        assert reviewed["patch"]["runtime_mutation"] is False

        graph = service.graph_intelligence(incident.incident_uuid)
        assert graph["summary"]["node_count"] >= 1
        assert graph["summary"]["edge_count"] >= 1
        first = graph["nodes"][0]["node_key"]
        path = service.graph_path(
            incident.incident_uuid,
            GraphPathRequest(source_node_key=first, target_node_key=first),
        )
        assert path["found"] is True
        search = service.global_search(
            "203.0.113.50",
            entity_types=["incident", "alert", "event", "entity", "indicator"],
            limit=50,
            offset=0,
        )
        assert search["returned"] >= 1


def test_ingestion_source_credentials_are_one_time_and_hashed(batch6_environment) -> None:
    scope, _ = batch6_environment
    with scope() as session:
        service = AdvancedSocService(session)
        created = service.create_ingestion_source(
            IngestionSourceCreate(
                name="Batch 6 Entra stream",
                connector_id="entra_id",
                rate_limit_per_minute=1200,
                allowed_ip_cidrs=["127.0.0.0/8"],
                metadata={"environment": "test"},
            ),
            "admin",
        )
        machine_key = created["api_key"]
        assert machine_key.startswith("tl_ing_")
        authenticated = service.authenticate_ingestion_source(machine_key, "127.0.0.1")
        assert authenticated.source_uuid == created["source_uuid"]
        listed = service.list_ingestion_sources()
        assert "api_key" not in listed[0]
        with pytest.raises(PermissionError):
            service.authenticate_ingestion_source("tl_ing_invalid_invalid_invalid", "127.0.0.1")


def test_batch6_openapi_has_advanced_soc_and_separate_machine_auth_boundary() -> None:
    settings = SecuritySettings(
        jwt_secret="batch6-openapi-test-secret-that-is-long-enough-123456789",
        jwt_issuer="threatlens-ai",
        jwt_audience="threatlens-api",
        access_token_minutes=15,
        refresh_token_hours=8,
        max_failed_logins=5,
        lockout_minutes=15,
        allowed_origins=("http://localhost",),
        trusted_hosts=("testserver", "localhost"),
        enable_development_docs=True,
        max_upload_bytes=10 * 1024 * 1024,
        max_upload_files=10,
        api_host="127.0.0.1",
        api_port=8000,
    )
    schema = create_app(settings).openapi()
    paths = schema["paths"]
    required = {
        "/api/v1/ingestion/sources",
        "/api/v1/ingest/realtime",
        "/api/v1/intel/feeds",
        "/api/v1/intel/indicators",
        "/api/v1/hunts/execute",
        "/api/v1/hunts/saved",
        "/api/v1/incidents/{incident_uuid}/case-operations",
        "/api/v1/response/playbooks",
        "/api/v1/response-executions/{execution_uuid}/approval",
        "/api/v1/response-executions/{execution_uuid}/execute",
        "/api/v1/detections/feedback",
        "/api/v1/detections/tunings",
        "/api/v1/incidents/{incident_uuid}/graph/intelligence",
        "/api/v1/search",
    }
    assert required <= set(paths)
    realtime = paths["/api/v1/ingest/realtime"]["post"]
    assert {"ThreatLensIngestKey": []} in realtime.get("security", [])
    scheme = schema["components"]["securitySchemes"]["ThreatLensIngestKey"]
    assert scheme["type"] == "apiKey"
    assert scheme["name"] == "X-ThreatLens-Ingest-Key"
    assert scheme["in"] == "header"
    for path in required - {"/api/v1/ingest/realtime"}:
        assert any(operation.get("security") for operation in paths[path].values() if isinstance(operation, dict))


def test_batch6_migration_chain_and_models_present() -> None:
    migration = (ROOT / "migrations" / "versions" / "f6a6c0b60001_batch6_advanced_soc.py").read_text(encoding="utf-8")
    assert 'revision: str = "f6a6c0b60001"' in migration
    assert 'down_revision: str | None = "e9b5a1300001"' in migration
    required_tables = {
        "ingestion_sources",
        "realtime_ingress_events",
        "threat_intel_feeds",
        "threat_indicators",
        "threat_intel_hits",
        "saved_hunts",
        "hunt_executions",
        "incident_case_profiles",
        "incident_tasks",
        "incident_handoffs",
        "evidence_custody_events",
        "response_playbooks",
        "response_executions",
        "detection_feedback",
        "detection_tunings",
    }
    assert required_tables <= set(Base.metadata.tables)


def test_batch6_response_frontend_exposes_governed_approval_and_execution() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "AdvancedSocPages.tsx").read_text(encoding="utf-8")
    assert "/response-executions/${executionUuid}/approval" in source
    assert "/response-executions/${executionUuid}/execute" in source
    assert "response:approve" in source
    assert "response:execute" in source
    assert "Approve response" in source
    assert "Record approved simulated execution" in source
    assert "requester cannot approve" in source.lower()
