from __future__ import annotations

import json

from sqlalchemy import func, select

from database.models import (
    AnalysisSessionModel,
    AttackGraphSnapshotModel,
    AuditLogModel,
    CorrelationRunModel,
    EvidenceCustodyEventModel,
    EvidenceModel,
    HuntExecutionModel,
    IncidentModel,
    InvestigationNoteModel,
    RagInvestigationQueryModel,
    SavedHuntModel,
    ThreatIndicatorModel,
    ThreatIntelFeedModel,
    ThreatIntelHitModel,
)
from database.session import session_scope

ANALYSIS_UUID = "93aa1e45-480d-4dbb-aae1-e4fd12db3c15"
INCIDENT_UUID = "95275eea-92f9-498a-a975-74f53906e803"
RAG_MARKER = "PHASE3E-UAT-V1"

EXPECTED = {
    "events": 10,
    "alerts": 8,
    "incidents": 5,
    "quarantined": 0,
}


def count_all(db, model):
    return int(db.scalar(select(func.count(model.id))) or 0)


def count_where(db, model, column_name, value):
    column = getattr(model, column_name)
    return int(
        db.scalar(select(func.count(model.id)).where(column == value)) or 0
    )


def count_graph_snapshots_for_analysis(db, analysis_id):
    statement = (
        select(func.count(AttackGraphSnapshotModel.id))
        .select_from(AttackGraphSnapshotModel)
        .join(
            CorrelationRunModel,
            AttackGraphSnapshotModel.correlation_run_id
            == CorrelationRunModel.id,
        )
        .where(CorrelationRunModel.analysis_session_id == analysis_id)
    )
    return int(db.scalar(statement) or 0)


def resolve():
    with session_scope() as db:
        analysis = db.scalar(
            select(AnalysisSessionModel).where(
                AnalysisSessionModel.session_uuid == ANALYSIS_UUID
            )
        )
        if analysis is None:
            raise RuntimeError("Golden Demo reference analysis is missing.")

        actual = {
            "events": int(analysis.total_events),
            "alerts": int(analysis.total_alerts),
            "incidents": int(analysis.total_incidents),
            "quarantined": int(analysis.total_quarantined),
        }

        if actual != EXPECTED:
            raise RuntimeError(
                f"Golden Demo storyline drift: {actual} != {EXPECTED}"
            )

        if float(analysis.parse_success_rate) != 1.0:
            raise RuntimeError(
                "Golden Demo reference parse-success rate is not 1.0."
            )

        incident = db.scalar(
            select(IncidentModel).where(
                IncidentModel.incident_uuid == INCIDENT_UUID
            )
        )
        if incident is None:
            raise RuntimeError("Golden Demo integrated incident is missing.")

        if incident.analysis_session_id != analysis.id:
            raise RuntimeError(
                "Golden Demo incident no longer belongs to reference analysis."
            )

        marker = db.scalars(
            select(RagInvestigationQueryModel)
            .where(
                RagInvestigationQueryModel.question.contains(RAG_MARKER)
            )
            .order_by(RagInvestigationQueryModel.id.desc())
            .limit(1)
        ).first()

        if marker is None or marker.incident_id != incident.id:
            raise RuntimeError(
                "Golden Demo RAG marker no longer resolves to locked incident."
            )

        notes = count_where(
            db,
            InvestigationNoteModel,
            "incident_id",
            incident.id,
        )
        evidence = count_where(
            db,
            EvidenceModel,
            "incident_id",
            incident.id,
        )
        rag_queries = count_where(
            db,
            RagInvestigationQueryModel,
            "incident_id",
            incident.id,
        )

        evidence_ids = list(
            db.scalars(
                select(EvidenceModel.id).where(
                    EvidenceModel.incident_id == incident.id
                )
            ).all()
        )

        custody = 0
        if evidence_ids:
            custody = int(
                db.scalar(
                    select(func.count(EvidenceCustodyEventModel.id)).where(
                        EvidenceCustodyEventModel.evidence_id.in_(evidence_ids)
                    )
                )
                or 0
            )

        capabilities = {
            "notes": notes,
            "evidence": evidence,
            "custody_events": custody,
            "rag_queries": rag_queries,
            "graph_snapshots": count_graph_snapshots_for_analysis(
                db,
                analysis.id,
            ),
            "threat_intel_feeds": count_all(
                db,
                ThreatIntelFeedModel,
            ),
            "threat_indicators": count_all(
                db,
                ThreatIndicatorModel,
            ),
            "threat_intel_hits": count_all(
                db,
                ThreatIntelHitModel,
            ),
            "saved_hunts": count_all(
                db,
                SavedHuntModel,
            ),
            "hunt_executions": count_all(
                db,
                HuntExecutionModel,
            ),
            "audit_records": count_all(
                db,
                AuditLogModel,
            ),
        }

        missing = sorted(
            name
            for name, value in capabilities.items()
            if int(value) < 1
        )

        if missing:
            raise RuntimeError(
                "Golden Demo capability evidence missing: "
                + ", ".join(missing)
            )

        return {
            "status": "PASS",
            "context": {
                "analysis_uuid": analysis.session_uuid,
                "incident_uuid": incident.incident_uuid,
                "incident_title": incident.title,
                **actual,
                **capabilities,
            },
        }


if __name__ == "__main__":
    print(
        json.dumps(
            resolve(),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
