
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import DatabaseSession, RequireReportRead
from api.rbac import Permission
from app.application_service import ThreatLensApplicationService
from core.report_generator import generate_incident_report
from database.models import AiInvestigationJobModel, IncidentModel
from jobs.models import AiJobStatus

router = APIRouter(prefix="/reports", tags=["reports"])

PDF_RESPONSE = {
    200: {
        "description": "Generated ThreatLens incident investigation PDF.",
        "content": {
            "application/pdf": {
                "schema": {"type": "string", "format": "binary"},
            }
        },
    }
}


MAX_SAVED_AI_ANSWERS_PER_INCIDENT = 5


def _saved_ai_investigations(
    session: Session, incident_uuids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """Load only completed, persisted answers for incidents in this analysis."""
    if not incident_uuids:
        return {}
    investigations: dict[str, list[dict[str, Any]]] = {}
    incidents = session.scalars(
        select(IncidentModel).where(IncidentModel.incident_uuid.in_(incident_uuids))
    ).all()
    for incident in incidents:
        jobs = session.scalars(
            select(AiInvestigationJobModel)
            .where(
                AiInvestigationJobModel.incident_id == incident.id,
                AiInvestigationJobModel.status == AiJobStatus.SUCCEEDED.value,
            )
            .order_by(
                AiInvestigationJobModel.completed_at.desc(),
                AiInvestigationJobModel.created_at.desc(),
            )
            .limit(MAX_SAVED_AI_ANSWERS_PER_INCIDENT)
        ).all()
        records = []
        for job in jobs:
            response = job.result_json
            if not isinstance(response, dict) or not str(response.get("assessment") or "").strip():
                continue
            records.append({
                "job_uuid": job.job_uuid,
                "query_uuid": job.result_query_uuid,
                "actor": job.actor,
                "question": job.question,
                "completed_at": job.completed_at,
                "response": response,
            })
        investigations[incident.incident_uuid] = records
    return investigations


@router.get(
    "/analyses/{session_uuid}/incident.pdf",
    response_class=Response,
    responses=PDF_RESPONSE,
)
def incident_report(
    session_uuid: str,
    principal: RequireReportRead,
    session: DatabaseSession,
) -> Response:
    """Generate an authorized incident report from persisted analysis/case evidence."""

    service = ThreatLensApplicationService()
    pipeline = service.load_analysis(session_uuid)
    metadata = service.get_analysis_metadata(session_uuid)
    if pipeline is None or metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "analysis_not_found",
                "message": "Analysis session was not found.",
            },
        )

    incident_details = []
    incident_uuids: list[str] = []
    if not pipeline.incidents_df.empty and "incident_uuid" in pipeline.incidents_df.columns:
        for incident_uuid in pipeline.incidents_df["incident_uuid"].dropna().astype(str):
            incident_uuids.append(incident_uuid)
            details = service.get_incident_details(incident_uuid)
            if details is not None:
                incident_details.append(details)

    ai_investigations = None
    if {Permission.RAG_QUERY, Permission.INCIDENT_READ} <= principal.permissions:
        ai_investigations = _saved_ai_investigations(session, incident_uuids)

    report_path = Path(
        generate_incident_report(
            pipeline.events_df,
            pipeline.alerts_df,
            pipeline.incidents_df,
            pipeline.timeline_df,
            session_uuid=session_uuid,
            analysis_name=str(metadata.get("name") or "ThreatLens analysis"),
            analyst=principal.username,
            incident_details=incident_details,
            ai_investigations=ai_investigations,
        )
    )
    filename = report_path.name.replace('"', "")
    try:
        payload = report_path.read_bytes()
    finally:
        report_path.unlink(missing_ok=True)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-SHA256": hashlib.sha256(payload).hexdigest(),
        },
    )
