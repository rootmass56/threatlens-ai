from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Query, Request, status

from advanced_soc.schemas import (
    CaseProfileUpdate,
    CustodyEventCreate,
    DetectionFeedbackCreate,
    DetectionTuningCreate,
    DetectionTuningReview,
    GraphPathRequest,
    HandoffCreate,
    HuntQuery,
    IncidentTaskCreate,
    IncidentTaskUpdate,
    IngestionSourceCreate,
    IngestionSourceUpdate,
    PlaybookApprovalRequest,
    PlaybookCreate,
    PlaybookExecutionComplete,
    PlaybookExecutionRequest,
    RealtimeIngestRequest,
    SavedHuntCreate,
    ThreatFeedCreate,
    ThreatIntelImportRequest,
)
from advanced_soc.service import AdvancedSocService
from api.dependencies import (
    DatabaseSession,
    RequireCaseOperate,
    RequireDetectionFeedback,
    RequireDetectionManage,
    RequireGraphRead,
    RequireHuntExecute,
    RequireHuntManage,
    RequireIngestManage,
    RequireIngestRead,
    RequireIntelManage,
    RequireIntelRead,
    RequireResponseApprove,
    RequireResponseExecute,
    RequireResponseRequest,
    RequireSearchRead,
)

router = APIRouter(tags=["advanced-soc"])


def _not_found(error: Exception) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": "not_found", "message": str(error)})


def _invalid(error: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail={"code": "invalid_request", "message": str(error)})


def _forbidden(error: Exception) -> HTTPException:
    return HTTPException(status_code=403, detail={"code": "permission_denied", "message": str(error)})


# ============================================================================
# 6A - real-time ingestion
# ============================================================================


@router.post("/ingestion/sources", status_code=201)
def create_ingestion_source(
    payload: IngestionSourceCreate,
    principal: RequireIngestManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).create_ingestion_source(payload, principal.username)
    except (LookupError, ValueError) as error:
        raise _invalid(error) from error


@router.get("/ingestion/sources")
def list_ingestion_sources(
    principal: RequireIngestRead,
    session: DatabaseSession,
) -> dict:
    del principal
    items = AdvancedSocService(session).list_ingestion_sources()
    return {"items": items, "count": len(items)}


@router.patch("/ingestion/sources/{source_uuid}")
def update_ingestion_source(
    source_uuid: str,
    payload: IngestionSourceUpdate,
    principal: RequireIngestManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).update_ingestion_source(source_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except ValueError as error:
        raise _invalid(error) from error


@router.post("/ingestion/sources/{source_uuid}/rotate-key")
def rotate_ingestion_key(
    source_uuid: str,
    principal: RequireIngestManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).rotate_ingestion_key(source_uuid, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.post("/ingest/realtime", status_code=status.HTTP_202_ACCEPTED)
def ingest_realtime(
    payload: RealtimeIngestRequest,
    request: Request,
    session: DatabaseSession,
    ingest_key: str = Header(min_length=16, alias="X-ThreatLens-Ingest-Key"),
) -> dict:
    """Machine-to-machine telemetry boundary; uses a hashed source credential, not a user JWT."""
    service = AdvancedSocService(session)
    source_ip = request.client.host if request.client else None
    try:
        source = service.authenticate_ingestion_source(ingest_key, source_ip)
        return service.accept_realtime(source, payload, source_ip)
    except PermissionError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_ingestion_credential", "message": str(error)},
        ) from error
    except RuntimeError as error:
        if str(error) == "realtime_ingestion_rate_limit":
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"code": "ingestion_rate_limited", "message": "This ingestion source exceeded its configured per-minute budget."},
                headers={"Retry-After": "60"},
            ) from error
        raise


@router.get("/ingestion/recent")
def recent_ingress(
    principal: RequireIngestRead,
    session: DatabaseSession,
    limit: int = Query(default=200, ge=1, le=500),
) -> dict:
    del principal
    items = AdvancedSocService(session).recent_ingress(limit)
    return {"items": items, "count": len(items)}


# ============================================================================
# 6B - threat intelligence
# ============================================================================


@router.post("/intel/feeds", status_code=201)
def create_intel_feed(
    payload: ThreatFeedCreate,
    principal: RequireIntelManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).create_feed(payload, principal.username)
    except Exception as error:
        raise _invalid(error) from error


@router.get("/intel/feeds")
def list_intel_feeds(principal: RequireIntelRead, session: DatabaseSession) -> dict:
    del principal
    items = AdvancedSocService(session).list_feeds()
    return {"items": items, "count": len(items)}


@router.post("/intel/feeds/{feed_uuid}/import")
def import_intel(
    feed_uuid: str,
    payload: ThreatIntelImportRequest,
    principal: RequireIntelManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).import_indicators(feed_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except ValueError as error:
        raise _invalid(error) from error


@router.get("/intel/indicators")
def list_indicators(
    principal: RequireIntelRead,
    session: DatabaseSession,
    indicator_type: str | None = None,
    active_only: bool = True,
    limit: int = Query(default=250, ge=1, le=1000),
) -> dict:
    del principal
    items = AdvancedSocService(session).list_indicators(
        indicator_type=indicator_type,
        active_only=active_only,
        limit=limit,
    )
    return {"items": items, "count": len(items)}


@router.post("/intel/enrich/analyses/{session_uuid}")
def enrich_analysis(
    session_uuid: str,
    principal: RequireIntelManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).enrich_analysis(session_uuid, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/intel/hits")
def list_intel_hits(
    principal: RequireIntelRead,
    session: DatabaseSession,
    incident_uuid: str | None = None,
    limit: int = Query(default=250, ge=1, le=1000),
) -> dict:
    del principal
    try:
        items = AdvancedSocService(session).list_intel_hits(incident_uuid=incident_uuid, limit=limit)
    except LookupError as error:
        raise _not_found(error) from error
    return {"items": items, "count": len(items), "authority": "external_intelligence_enrichment_only"}


# ============================================================================
# 6C - read-only threat hunting
# ============================================================================


@router.post("/hunts/execute")
def execute_hunt(
    payload: HuntQuery,
    principal: RequireHuntExecute,
    session: DatabaseSession,
) -> dict:
    return AdvancedSocService(session).execute_hunt(payload, principal.username)


@router.post("/hunts/saved", status_code=201)
def save_hunt(
    payload: SavedHuntCreate,
    principal: RequireHuntManage,
    session: DatabaseSession,
) -> dict:
    return AdvancedSocService(session).save_hunt(payload, principal.username)


@router.get("/hunts/saved")
def list_saved_hunts(
    principal: RequireHuntExecute,
    session: DatabaseSession,
) -> dict:
    items = AdvancedSocService(session).list_saved_hunts(principal.username)
    return {"items": items, "count": len(items)}


@router.post("/hunts/saved/{hunt_uuid}/execute")
def execute_saved_hunt(
    hunt_uuid: str,
    principal: RequireHuntExecute,
    session: DatabaseSession,
) -> dict:
    service = AdvancedSocService(session)
    from database.models import SavedHuntModel
    from sqlalchemy import select

    row = session.scalar(select(SavedHuntModel).where(SavedHuntModel.hunt_uuid == hunt_uuid))
    if row is None or (row.owner != principal.username and not row.shared):
        raise HTTPException(status_code=404, detail={"code": "hunt_not_found", "message": "Saved hunt was not found."})
    return service.execute_hunt(HuntQuery.model_validate(row.query_json), principal.username, saved_hunt_id=row.id)


# ============================================================================
# 6D - case operations and evidence chain
# ============================================================================


@router.get("/incidents/{incident_uuid}/case-operations")
def case_operations(
    incident_uuid: str,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    del principal
    try:
        return AdvancedSocService(session).get_case_operations(incident_uuid)
    except LookupError as error:
        raise _not_found(error) from error


@router.patch("/incidents/{incident_uuid}/case-operations/profile")
def update_case_profile(
    incident_uuid: str,
    payload: CaseProfileUpdate,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).update_case_profile(incident_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.post("/incidents/{incident_uuid}/tasks", status_code=201)
def create_incident_task(
    incident_uuid: str,
    payload: IncidentTaskCreate,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).create_task(incident_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.patch("/incident-tasks/{task_uuid}")
def update_incident_task(
    task_uuid: str,
    payload: IncidentTaskUpdate,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).update_task(task_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.post("/incidents/{incident_uuid}/handoffs", status_code=201)
def create_handoff(
    incident_uuid: str,
    payload: HandoffCreate,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).create_handoff(incident_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.post("/incident-handoffs/{handoff_uuid}/accept")
def accept_handoff(
    handoff_uuid: str,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).accept_handoff(handoff_uuid, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except PermissionError as error:
        raise _forbidden(error) from error


@router.post("/evidence/{evidence_uuid}/custody", status_code=201)
def add_evidence_custody(
    evidence_uuid: str,
    payload: CustodyEventCreate,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).add_custody_event(evidence_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/evidence/{evidence_uuid}/custody")
def evidence_custody(
    evidence_uuid: str,
    principal: RequireCaseOperate,
    session: DatabaseSession,
) -> dict:
    del principal
    try:
        items = AdvancedSocService(session).list_custody(evidence_uuid)
    except LookupError as error:
        raise _not_found(error) from error
    return {"items": items, "count": len(items)}


# ============================================================================
# 6E - human approval-gated response playbooks
# ============================================================================


@router.get("/response/playbooks")
def list_playbooks(
    principal: RequireResponseRequest,
    session: DatabaseSession,
) -> dict:
    del principal
    items = AdvancedSocService(session).list_playbooks()
    return {"items": items, "count": len(items), "policy": "human_approval_required_no_autonomous_destructive_actions"}


@router.post("/response/playbooks", status_code=201)
def create_playbook(
    payload: PlaybookCreate,
    principal: RequireResponseApprove,
    session: DatabaseSession,
) -> dict:
    return AdvancedSocService(session).create_playbook(payload, principal.username)


@router.post("/incidents/{incident_uuid}/response-executions", status_code=201)
def request_playbook_execution(
    incident_uuid: str,
    payload: PlaybookExecutionRequest,
    principal: RequireResponseRequest,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).request_playbook(incident_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/incidents/{incident_uuid}/response-executions")
def list_playbook_executions(
    incident_uuid: str,
    principal: RequireResponseRequest,
    session: DatabaseSession,
) -> dict:
    del principal
    try:
        items = AdvancedSocService(session).list_executions(incident_uuid)
    except LookupError as error:
        raise _not_found(error) from error
    return {"items": items, "count": len(items)}


@router.post("/response-executions/{execution_uuid}/approval")
def approve_playbook_execution(
    execution_uuid: str,
    payload: PlaybookApprovalRequest,
    principal: RequireResponseApprove,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).approve_execution(execution_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except ValueError as error:
        raise _invalid(error) from error


@router.post("/response-executions/{execution_uuid}/execute")
def complete_playbook_execution(
    execution_uuid: str,
    payload: PlaybookExecutionComplete,
    principal: RequireResponseExecute,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).complete_execution(execution_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except PermissionError as error:
        raise _forbidden(error) from error


# ============================================================================
# 6F - detection feedback/tuning governance
# ============================================================================


@router.post("/detections/feedback", status_code=201)
def create_detection_feedback(
    payload: DetectionFeedbackCreate,
    principal: RequireDetectionFeedback,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).create_detection_feedback(payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/detections/effectiveness")
def detection_effectiveness(
    principal: RequireDetectionFeedback,
    session: DatabaseSession,
) -> dict:
    del principal
    items = AdvancedSocService(session).detection_metrics()
    return {"items": items, "count": len(items)}


@router.post("/detections/tunings", status_code=201)
def propose_detection_tuning(
    payload: DetectionTuningCreate,
    principal: RequireDetectionManage,
    session: DatabaseSession,
) -> dict:
    return AdvancedSocService(session).propose_tuning(payload, principal.username)


@router.get("/detections/tunings")
def list_detection_tunings(
    principal: RequireDetectionManage,
    session: DatabaseSession,
) -> dict:
    del principal
    items = AdvancedSocService(session).list_tunings()
    return {"items": items, "count": len(items), "runtime_mutation": False}


@router.post("/detections/tunings/{tuning_uuid}/review")
def review_detection_tuning(
    tuning_uuid: str,
    payload: DetectionTuningReview,
    principal: RequireDetectionManage,
    session: DatabaseSession,
) -> dict:
    try:
        return AdvancedSocService(session).review_tuning(tuning_uuid, payload, principal.username)
    except LookupError as error:
        raise _not_found(error) from error
    except ValueError as error:
        raise _invalid(error) from error


# ============================================================================
# 6H - graph intelligence + search/scale API
# ============================================================================


@router.get("/incidents/{incident_uuid}/graph/intelligence")
def graph_intelligence(
    incident_uuid: str,
    principal: RequireGraphRead,
    session: DatabaseSession,
    minimum_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    entity_type: str | None = None,
) -> dict:
    del principal
    try:
        return AdvancedSocService(session).graph_intelligence(
            incident_uuid,
            minimum_confidence=minimum_confidence,
            entity_type=entity_type,
        )
    except LookupError as error:
        raise _not_found(error) from error


@router.post("/incidents/{incident_uuid}/graph/path")
def graph_path(
    incident_uuid: str,
    payload: GraphPathRequest,
    principal: RequireGraphRead,
    session: DatabaseSession,
) -> dict:
    del principal
    try:
        return AdvancedSocService(session).graph_path(incident_uuid, payload)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/entities/{entity_uuid}/timeline")
def entity_timeline(
    entity_uuid: str,
    principal: RequireGraphRead,
    session: DatabaseSession,
    limit: int = Query(default=250, ge=1, le=1000),
) -> dict:
    del principal
    try:
        return AdvancedSocService(session).entity_timeline(entity_uuid, limit=limit)
    except LookupError as error:
        raise _not_found(error) from error


@router.get("/search")
def global_search(
    principal: RequireSearchRead,
    session: DatabaseSession,
    q: str = Query(min_length=2, max_length=512),
    entity_types: str = Query(default="incident,alert,event,entity,indicator"),
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> dict:
    del principal
    allowed = {"incident", "alert", "event", "entity", "indicator"}
    selected = [item.strip() for item in entity_types.split(",") if item.strip() in allowed]
    if not selected:
        raise HTTPException(status_code=422, detail={"code": "invalid_search_types", "message": "No supported entity types were selected."})
    return AdvancedSocService(session).global_search(q, entity_types=selected, limit=limit, offset=offset)
