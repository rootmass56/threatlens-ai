from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from advanced_soc.schemas import (
    CaseProfileUpdate,
    CustodyEventCreate,
    DetectionFeedbackCreate,
    HuntQuery,
    IncidentTaskCreate,
    PlaybookApprovalRequest,
    PlaybookExecutionComplete,
    PlaybookExecutionRequest,
    SavedHuntCreate,
    ThreatFeedCreate,
    ThreatIndicatorInput,
    ThreatIntelImportRequest,
)
from advanced_soc.service import AdvancedSocService
from app.application_service import ThreatLensApplicationService
from core.pipeline import AnalysisPipelineResult, SourceInput
from database.models import (
    AlertModel,
    AnalysisSessionModel,
    AttackGraphSnapshotModel,
    AuditLogModel,
    CorrelationRunModel,
    DetectionFeedbackModel,
    EventModel,
    EvidenceCustodyEventModel,
    EvidenceModel,
    HuntExecutionModel,
    IncidentCaseProfileModel,
    IncidentModel,
    IncidentTaskModel,
    InvestigationNoteModel,
    RagInvestigationQueryModel,
    ResponseExecutionModel,
    ResponsePlaybookModel,
    SavedHuntModel,
    ThreatIndicatorModel,
    ThreatIntelFeedModel,
    ThreatIntelHitModel,
)
from database.service import ThreatLensPersistenceService
from database.session import session_scope

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "demo" / "fixtures" / "enhanced_v2"

NAMESPACE = "THREATLENS-ENHANCED-GOLDEN-DEMO-V2"
ANALYSIS_NAME = f"{NAMESPACE} | Northstar Payroll Intrusion"
ACTOR = "demo:v2"
PRIMARY_ASSIGNEE = "tier2-analyst"
FEED_NAME = f"{NAMESPACE} Curated Intelligence"
HUNT_NAME = f"{NAMESPACE} Infrastructure Pivot"
TASK_TITLE = f"{NAMESPACE} Validate and contain FIN-WS-042"
EVIDENCE_DESCRIPTION = f"{NAMESPACE} immutable five-source telemetry bundle"
NOTE = (
    f"{NAMESPACE}: deterministic evidence confirms identity compromise, credential "
    "access, lateral movement, persistence, command-and-control, exfiltration-like "
    "DNS activity, and defense impairment. AI remains downstream and advisory."
)
RAG_QUESTION = (
    f"{NAMESPACE}: Using only persisted evidence and cited governed knowledge, explain "
    "the attack progression, highest-confidence findings, containment priorities, and "
    "important uncertainties. Do not convert threat-intelligence context into observed facts."
)

EXPECTED = {
    "events": 29,
    "alerts": 26,
    "incidents": 2,
    "quarantined": 0,
    "connectors": 5,
    "techniques": 19,
    "critical_alerts": 7,
    "graph_nodes": 76,
    "graph_edges": 300,
}

FIXTURES: tuple[tuple[str, str], ...] = (
    ("entra_identity.jsonl", "entra_id"),
    ("windows_security.jsonl", "windows_security"),
    ("sysmon.jsonl", "windows_sysmon"),
    ("suricata_eve.jsonl", "suricata_eve"),
    ("zeek.jsonl", "zeek"),
)

EXPECTED_DETECTIONS = {
    "entra_mfa_failure",
    "entra_privileged_role_assignment",
    "entra_risky_signin",
    "suricata_c2_alert",
    "suricata_dns_tunneling",
    "suricata_executable_transfer",
    "suricata_suspicious_http_post",
    "sysmon_encoded_powershell",
    "sysmon_lsass_access",
    "sysmon_registry_run_key",
    "sysmon_remote_thread_creation",
    "sysmon_sensitive_file_deleted",
    "sysmon_suspicious_rdp_connection",
    "windows_account_to_task_sequence",
    "windows_audit_log_cleared",
    "windows_encoded_powershell",
    "windows_explicit_credential_logon",
    "windows_failed_logons",
    "windows_privileged_group_member_added",
    "windows_scheduled_task_created",
    "windows_special_privileges_assigned",
    "windows_user_account_created",
    "zeek_executable_download",
    "zeek_long_dns_query",
    "zeek_suspicious_tls_sni",
}

SessionContextFactory = Callable[[], AbstractContextManager[Session]]


def build_sources() -> list[SourceInput]:
    sources: list[SourceInput] = []
    for filename, connector_id in FIXTURES:
        path = FIXTURE_ROOT / filename
        sources.append(
            SourceInput(
                raw_content=path.read_bytes(),
                filename=filename,
                connector_id=connector_id,
            )
        )
    return sources


def fixture_bundle_sha256() -> str:
    digest = hashlib.sha256()
    for filename, connector_id in FIXTURES:
        payload = (FIXTURE_ROOT / filename).read_bytes()
        digest.update(f"{connector_id}:{filename}:{len(payload)}\n".encode())
        digest.update(payload)
        digest.update(b"\n")
    return digest.hexdigest()


def validate_pipeline(result: AnalysisPipelineResult) -> dict[str, object]:
    graph = result.correlation_result
    if graph is None:
        raise RuntimeError("Enhanced v2 correlation result is missing.")
    actual = {
        "events": result.event_count,
        "alerts": result.alert_count,
        "incidents": result.incident_count,
        "quarantined": result.quarantined_count,
        "connectors": len(result.connector_ids),
        "techniques": len(set(result.alerts_df["mitre_technique_id"].dropna())),
        "critical_alerts": int((result.alerts_df["severity"] == "Critical").sum()),
        "graph_nodes": int(graph.metrics["graph_nodes"]),
        "graph_edges": int(graph.metrics["graph_edges"]),
    }
    if actual != EXPECTED:
        raise RuntimeError(f"Enhanced v2 deterministic drift: {actual} != {EXPECTED}")
    detections = set(result.alerts_df["detection_name"])
    if detections != EXPECTED_DETECTIONS:
        raise RuntimeError(
            "Enhanced v2 detection coverage drift: "
            f"missing={sorted(EXPECTED_DETECTIONS - detections)}, "
            f"unexpected={sorted(detections - EXPECTED_DETECTIONS)}"
        )
    if result.parse_success_rate != 1.0:
        raise RuntimeError("Enhanced v2 parse-success rate is not 1.0.")
    if set(result.connector_ids) != {connector for _, connector in FIXTURES}:
        raise RuntimeError("Enhanced v2 connector coverage drifted.")
    return actual


def _primary_incident(db: Session, analysis_id: int) -> IncidentModel:
    incident = db.scalar(
        select(IncidentModel)
        .where(IncidentModel.analysis_session_id == analysis_id)
        .order_by(
            IncidentModel.risk_score.desc(),
            IncidentModel.representative_alert_count.desc(),
            IncidentModel.id.asc(),
        )
        .limit(1)
    )
    if incident is None:
        raise RuntimeError("Enhanced v2 primary incident is missing.")
    return incident


def _ensure_operational_story(
    db: Session,
    *,
    analysis: AnalysisSessionModel,
    primary: IncidentModel,
) -> None:
    persistence = ThreatLensPersistenceService(db)
    advanced = AdvancedSocService(db)

    if primary.status == "open":
        persistence.update_incident_workflow(
            incident_uuid=primary.incident_uuid,
            status="investigating",
            assignee=PRIMARY_ASSIGNEE,
            priority="P1",
            actor=ACTOR,
        )

    note = db.scalar(
        select(InvestigationNoteModel).where(
            InvestigationNoteModel.incident_id == primary.id,
            InvestigationNoteModel.note == NOTE,
        )
    )
    if note is None:
        persistence.add_investigation_note(
            incident_uuid=primary.incident_uuid,
            author=ACTOR,
            note=NOTE,
        )

    evidence = db.scalar(
        select(EvidenceModel).where(
            EvidenceModel.incident_id == primary.id,
            EvidenceModel.description == EVIDENCE_DESCRIPTION,
        )
    )
    if evidence is None:
        evidence_uuid = persistence.register_evidence(
            incident_uuid=primary.incident_uuid,
            evidence_type="telemetry_bundle",
            description=EVIDENCE_DESCRIPTION,
            source_reference="demo/fixtures/enhanced_v2",
            sha256=fixture_bundle_sha256(),
            actor=ACTOR,
        )
        db.flush()
        evidence = db.scalar(
            select(EvidenceModel).where(EvidenceModel.evidence_uuid == evidence_uuid)
        )
    if evidence is None:
        raise RuntimeError("Enhanced v2 evidence registration failed.")

    custody = db.scalar(
        select(EvidenceCustodyEventModel).where(
            EvidenceCustodyEventModel.evidence_id == evidence.id,
            EvidenceCustodyEventModel.action == "verified",
        )
    )
    if custody is None:
        advanced.add_custody_event(
            evidence.evidence_uuid,
            CustodyEventCreate(
                action="verified",
                from_custodian="ThreatLens ingestion",
                to_custodian="Tier-2 SOC",
                location="ThreatLens evidence vault",
                notes="Fixture bundle SHA-256 verified before analyst review.",
                hash_verified=True,
            ),
            ACTOR,
        )

    profile = db.scalar(
        select(IncidentCaseProfileModel).where(
            IncidentCaseProfileModel.incident_id == primary.id
        )
    )
    if profile is None:
        advanced.update_case_profile(
            primary.incident_uuid,
            CaseProfileUpdate(
                team="Tier-2 SOC",
                escalation_level=2,
                disposition="true_positive",
                containment_status="in_progress",
                watchers=["incident-commander", PRIMARY_ASSIGNEE],
                tags=["enhanced-demo-v2", "identity", "endpoint", "c2"],
            ),
            ACTOR,
        )

    task = db.scalar(
        select(IncidentTaskModel).where(
            IncidentTaskModel.incident_id == primary.id,
            IncidentTaskModel.title == TASK_TITLE,
        )
    )
    if task is None:
        advanced.create_task(
            primary.incident_uuid,
            IncidentTaskCreate(
                task_type="containment",
                title=TASK_TITLE,
                description=(
                    "Validate the compromised identity, preserve volatile endpoint evidence, "
                    "isolate FIN-WS-042, and block confirmed command infrastructure."
                ),
                priority="P1",
                assignee=PRIMARY_ASSIGNEE,
                approval_required=True,
            ),
            ACTOR,
        )

    feed = db.scalar(
        select(ThreatIntelFeedModel).where(ThreatIntelFeedModel.name == FEED_NAME)
    )
    if feed is None:
        created = advanced.create_feed(
            ThreatFeedCreate(
                name=FEED_NAME,
                provider="ThreatLens Demo CTI",
                feed_format="curated_json",
                tlp="TLP:CLEAR",
                default_confidence=95,
                source_reference="demo/enhanced-v2-contract.json",
                metadata={"namespace": NAMESPACE, "authority": "enrichment_only"},
            ),
            ACTOR,
        )
        feed = db.scalar(
            select(ThreatIntelFeedModel).where(
                ThreatIntelFeedModel.feed_uuid == created["feed_uuid"]
            )
        )
    if feed is None:
        raise RuntimeError("Enhanced v2 intelligence feed creation failed.")

    indicators = (
        ("ipv4", "203.0.113.77", "credential-access"),
        ("ipv4", "198.51.100.88", "command-and-control"),
        ("ipv4", "198.51.100.53", "dns-infrastructure"),
        ("domain", "telemetry-gate.example", "command-and-control"),
        ("domain", "control-node.top", "command-and-control"),
    )
    existing = {
        (row.indicator_type, row.value_normalized)
        for row in db.scalars(
            select(ThreatIndicatorModel).where(ThreatIndicatorModel.feed_id == feed.id)
        ).all()
    }
    missing = [
        ThreatIndicatorInput(
            indicator_type=kind,
            value=value,
            confidence=95,
            malicious_score=0.95,
            tlp="TLP:CLEAR",
            tags=["enhanced-demo-v2", tag],
            source_reference="demo/enhanced-v2-contract.json",
        )
        for kind, value, tag in indicators
        if (kind, value.lower()) not in existing
    ]
    if missing:
        advanced.import_indicators(
            feed.feed_uuid,
            ThreatIntelImportRequest(indicators=missing),
            ACTOR,
        )

    event_ids = list(
        db.scalars(
            select(EventModel.id).where(EventModel.analysis_session_id == analysis.id)
        ).all()
    )
    hit_count = int(
        db.scalar(
            select(func.count(ThreatIntelHitModel.id)).where(
                ThreatIntelHitModel.event_id.in_(event_ids)
            )
        )
        or 0
    )
    if hit_count == 0:
        advanced.enrich_analysis(analysis.session_uuid, ACTOR)

    hunt = db.scalar(
        select(SavedHuntModel).where(
            SavedHuntModel.name == HUNT_NAME,
            SavedHuntModel.owner == ACTOR,
        )
    )
    hunt_query = HuntQuery(query="198.51.100.88", limit=100, offset=0, sort="asc")
    if hunt is None:
        saved = advanced.save_hunt(
            SavedHuntCreate(
                name=HUNT_NAME,
                description=(
                    "Pivot across all normalized telemetry for the v2 command infrastructure."
                ),
                query=hunt_query,
                shared=True,
            ),
            ACTOR,
        )
        hunt = db.scalar(
            select(SavedHuntModel).where(
                SavedHuntModel.hunt_uuid == saved["hunt_uuid"]
            )
        )
    if hunt is None:
        raise RuntimeError("Enhanced v2 saved hunt creation failed.")
    executed = db.scalar(
        select(HuntExecutionModel).where(HuntExecutionModel.saved_hunt_id == hunt.id)
    )
    if executed is None:
        advanced.execute_hunt(hunt_query, ACTOR, saved_hunt_id=hunt.id)

    feedback = db.scalar(
        select(DetectionFeedbackModel).where(
            DetectionFeedbackModel.incident_id == primary.id,
            DetectionFeedbackModel.actor == ACTOR,
        )
    )
    if feedback is None:
        critical_alert = db.scalar(
            select(AlertModel)
            .where(
                AlertModel.analysis_session_id == analysis.id,
                AlertModel.severity == "Critical",
            )
            .order_by(AlertModel.risk_score.desc(), AlertModel.id.asc())
            .limit(1)
        )
        if critical_alert is None:
            raise RuntimeError("Enhanced v2 critical alert is missing.")
        advanced.create_detection_feedback(
            DetectionFeedbackCreate(
                alert_uuid=critical_alert.alert_uuid,
                incident_uuid=primary.incident_uuid,
                verdict="true_positive",
                reason="Confirmed by the deterministic enhanced-v2 evidence chain.",
            ),
            ACTOR,
        )

    execution = db.scalar(
        select(ResponseExecutionModel).where(
            ResponseExecutionModel.incident_id == primary.id,
            ResponseExecutionModel.requested_by == ACTOR,
        )
    )
    if execution is None:
        advanced.ensure_default_playbooks()
        playbook = db.scalar(
            select(ResponsePlaybookModel).where(
                ResponsePlaybookModel.name == "Endpoint Isolation"
            )
        )
        if playbook is None:
            raise RuntimeError("Endpoint Isolation playbook is missing.")
        requested = advanced.request_playbook(
            primary.incident_uuid,
            PlaybookExecutionRequest(
                playbook_uuid=playbook.playbook_uuid,
                parameters={
                    "mode": "simulation",
                    "hostname": "FIN-WS-042",
                    "namespace": NAMESPACE,
                },
            ),
            ACTOR,
        )
        advanced.approve_execution(
            requested["execution_uuid"],
            PlaybookApprovalRequest(
                approved=True,
                note="Demo simulation approved after evidence and hash verification.",
            ),
            "demo:v2:incident-commander",
        )
        advanced.complete_execution(
            requested["execution_uuid"],
            PlaybookExecutionComplete(
                outcome="success",
                result={"simulated": True, "hostname": "FIN-WS-042"},
                rollback_notes="No production mutation was performed.",
            ),
            "demo:v2:senior-analyst",
        )


def _ensure_rag_query(db: Session, primary: IncidentModel) -> None:
    existing = db.scalar(
        select(RagInvestigationQueryModel)
        .where(
            RagInvestigationQueryModel.incident_id == primary.id,
            RagInvestigationQueryModel.question == RAG_QUESTION,
        )
        .order_by(RagInvestigationQueryModel.id.desc())
        .limit(1)
    )
    if (
        existing is not None
        and existing.response_status in {"answered", "partially_supported"}
        and existing.retrieval_count > 0
        and existing.grounding_score > 0
        and bool(existing.citation_ids_json)
    ):
        return
    from rag.models import RagAnalysisMode
    from rag.runtime import get_rag_runtime

    get_rag_runtime().query(
        db,
        incident_uuid=primary.incident_uuid,
        actor=ACTOR,
        question=RAG_QUESTION,
        analysis_mode=RagAnalysisMode.DEEP,
    )


def seed(
    *,
    session_context_factory: SessionContextFactory = session_scope,
    include_rag: bool = False,
) -> dict[str, object]:
    sources = build_sources()
    execution = ThreatLensApplicationService(
        session_context_factory=session_context_factory
    ).analyze_and_persist_sources(
        analysis_name=ANALYSIS_NAME,
        sources=sources,
        actor=ACTOR,
        allow_duplicate=False,
    )
    validate_pipeline(execution.pipeline)
    if execution.session_uuid is None:
        raise RuntimeError("Enhanced v2 analysis did not resolve to a persisted session.")

    with session_context_factory() as db:
        analysis = db.scalar(
            select(AnalysisSessionModel).where(
                AnalysisSessionModel.session_uuid == execution.session_uuid
            )
        )
        if analysis is None:
            raise RuntimeError("Enhanced v2 persisted analysis is missing.")
        primary = _primary_incident(db, analysis.id)
        _ensure_operational_story(db, analysis=analysis, primary=primary)
        if include_rag:
            _ensure_rag_query(db, primary)

    return resolve(
        session_context_factory=session_context_factory,
        require_rag=include_rag,
    )


def _count(db: Session, model, *criteria) -> int:
    statement = select(func.count(model.id))
    if criteria:
        statement = statement.where(*criteria)
    return int(db.scalar(statement) or 0)


def resolve(
    *,
    session_context_factory: SessionContextFactory = session_scope,
    require_rag: bool = False,
) -> dict[str, object]:
    with session_context_factory() as db:
        analysis = db.scalar(
            select(AnalysisSessionModel)
            .where(AnalysisSessionModel.name == ANALYSIS_NAME)
            .order_by(AnalysisSessionModel.id.desc())
            .limit(1)
        )
        if analysis is None:
            raise RuntimeError("Enhanced v2 analysis is missing; run the seed command.")
        actual = {
            "events": int(analysis.total_events),
            "alerts": int(analysis.total_alerts),
            "incidents": int(analysis.total_incidents),
            "quarantined": int(analysis.total_quarantined),
        }
        if actual != {key: EXPECTED[key] for key in actual}:
            raise RuntimeError(f"Enhanced v2 persisted drift: {actual}")
        if float(analysis.parse_success_rate) != 1.0:
            raise RuntimeError("Enhanced v2 persisted parse-success rate is not 1.0.")

        incidents = db.scalars(
            select(IncidentModel)
            .where(IncidentModel.analysis_session_id == analysis.id)
            .order_by(
                IncidentModel.risk_score.desc(),
                IncidentModel.representative_alert_count.desc(),
                IncidentModel.id.asc(),
            )
        ).all()
        primary = _primary_incident(db, analysis.id)
        incident_ids = [item.id for item in incidents]
        evidence_ids = list(
            db.scalars(
                select(EvidenceModel.id).where(EvidenceModel.incident_id.in_(incident_ids))
            ).all()
        )
        event_ids = list(
            db.scalars(
                select(EventModel.id).where(EventModel.analysis_session_id == analysis.id)
            ).all()
        )
        feed = db.scalar(
            select(ThreatIntelFeedModel).where(ThreatIntelFeedModel.name == FEED_NAME)
        )
        hunt = db.scalar(
            select(SavedHuntModel).where(
                SavedHuntModel.name == HUNT_NAME,
                SavedHuntModel.owner == ACTOR,
            )
        )
        graph_snapshots = int(
            db.scalar(
                select(func.count(AttackGraphSnapshotModel.id))
                .select_from(AttackGraphSnapshotModel)
                .join(
                    CorrelationRunModel,
                    AttackGraphSnapshotModel.correlation_run_id == CorrelationRunModel.id,
                )
                .where(CorrelationRunModel.analysis_session_id == analysis.id)
            )
            or 0
        )
        rag_query = db.scalar(
            select(RagInvestigationQueryModel)
            .where(
                RagInvestigationQueryModel.incident_id == primary.id,
                RagInvestigationQueryModel.question == RAG_QUESTION,
            )
            .order_by(RagInvestigationQueryModel.id.desc())
            .limit(1)
        )
        capabilities = {
            "notes": _count(
                db, InvestigationNoteModel, InvestigationNoteModel.incident_id.in_(incident_ids)
            ),
            "evidence": _count(
                db, EvidenceModel, EvidenceModel.incident_id.in_(incident_ids)
            ),
            "custody_events": (
                _count(
                    db,
                    EvidenceCustodyEventModel,
                    EvidenceCustodyEventModel.evidence_id.in_(evidence_ids),
                )
                if evidence_ids
                else 0
            ),
            "rag_queries": _count(
                db,
                RagInvestigationQueryModel,
                RagInvestigationQueryModel.incident_id == primary.id,
                RagInvestigationQueryModel.question == RAG_QUESTION,
            ),
            "graph_snapshots": graph_snapshots,
            "threat_intel_indicators": (
                _count(
                    db,
                    ThreatIndicatorModel,
                    ThreatIndicatorModel.feed_id == feed.id,
                )
                if feed
                else 0
            ),
            "threat_intel_hits": (
                _count(
                    db,
                    ThreatIntelHitModel,
                    ThreatIntelHitModel.event_id.in_(event_ids),
                )
                if event_ids
                else 0
            ),
            "saved_hunts": 1 if hunt else 0,
            "hunt_executions": (
                _count(
                    db,
                    HuntExecutionModel,
                    HuntExecutionModel.saved_hunt_id == hunt.id,
                )
                if hunt
                else 0
            ),
            "case_profiles": _count(
                db,
                IncidentCaseProfileModel,
                IncidentCaseProfileModel.incident_id == primary.id,
            ),
            "case_tasks": _count(
                db, IncidentTaskModel, IncidentTaskModel.incident_id == primary.id
            ),
            "response_executions": _count(
                db,
                ResponseExecutionModel,
                ResponseExecutionModel.incident_id == primary.id,
            ),
            "detection_feedback": _count(
                db,
                DetectionFeedbackModel,
                DetectionFeedbackModel.incident_id == primary.id,
            ),
            "audit_records": _count(db, AuditLogModel, AuditLogModel.actor == ACTOR),
        }
        required_minimums = {
            "notes": 1,
            "evidence": 1,
            "custody_events": 1,
            "graph_snapshots": 1,
            "threat_intel_indicators": 5,
            "threat_intel_hits": 1,
            "saved_hunts": 1,
            "hunt_executions": 1,
            "case_profiles": 1,
            "case_tasks": 1,
            "response_executions": 1,
            "detection_feedback": 1,
            "audit_records": 1,
        }
        if require_rag:
            required_minimums["rag_queries"] = 1
        missing = sorted(
            f"{name}<{minimum}"
            for name, minimum in required_minimums.items()
            if capabilities[name] < minimum
        )
        if missing:
            raise RuntimeError(
                "Enhanced v2 capability evidence missing: " + ", ".join(missing)
            )
        if require_rag and (
            rag_query is None
            or rag_query.response_status not in {"answered", "partially_supported"}
            or rag_query.retrieval_count < 1
            or rag_query.grounding_score <= 0
            or not rag_query.citation_ids_json
        ):
            raise RuntimeError(
                "Enhanced v2 grounded RAG result is missing retrieved, cited support."
            )
        return {
            "status": "PASS",
            "contract": NAMESPACE,
            "context": {
                "analysis_uuid": analysis.session_uuid,
                "primary_incident_uuid": primary.incident_uuid,
                "primary_incident_title": primary.title,
                "incident_uuids": [item.incident_uuid for item in incidents],
                **actual,
                "connectors": EXPECTED["connectors"],
                "techniques": EXPECTED["techniques"],
                "critical_alerts": EXPECTED["critical_alerts"],
                "graph_nodes": EXPECTED["graph_nodes"],
                "graph_edges": EXPECTED["graph_edges"],
                "rag_status": rag_query.response_status if rag_query else None,
                "rag_grounding_score": rag_query.grounding_score if rag_query else None,
                "rag_citations": len(rag_query.citation_ids_json or []) if rag_query else 0,
                **capabilities,
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed or verify Enhanced Golden Demo v2.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    seed_parser = subcommands.add_parser("seed")
    seed_parser.add_argument(
        "--with-rag",
        action="store_true",
        help="Run and require the grounded deep-analysis question.",
    )
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument(
        "--require-rag",
        action="store_true",
        help="Require the grounded RAG record in addition to deterministic evidence.",
    )
    args = parser.parse_args()
    result = (
        seed(include_rag=args.with_rag)
        if args.command == "seed"
        else resolve(require_rag=args.require_rag)
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
