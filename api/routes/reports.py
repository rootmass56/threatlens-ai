
from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response, status

from api.dependencies import RequireReportRead
from app.application_service import ThreatLensApplicationService
from core.report_generator import generate_incident_report

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


@router.get(
    "/analyses/{session_uuid}/incident.pdf",
    response_class=Response,
    responses=PDF_RESPONSE,
)
def incident_report(
    session_uuid: str,
    principal: RequireReportRead,
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
    if not pipeline.incidents_df.empty and "incident_uuid" in pipeline.incidents_df.columns:
        for incident_uuid in pipeline.incidents_df["incident_uuid"].dropna().astype(str):
            details = service.get_incident_details(incident_uuid)
            if details is not None:
                incident_details.append(details)

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
