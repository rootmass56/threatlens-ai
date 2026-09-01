
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.dependencies import DatabaseSession, RequireRagManage, RequireRagQuery
from api.schemas import RagQueryRequest, RagReindexRequest
from database.service import ThreatLensPersistenceService
from rag.runtime import get_rag_runtime

router = APIRouter(tags=["rag"])


@router.get("/rag/health")
def rag_health(principal: RequireRagQuery) -> dict:
    del principal
    return get_rag_runtime().health().model_dump(mode="json")


@router.get("/rag/knowledge/status")
def rag_knowledge_status(principal: RequireRagQuery) -> dict:
    del principal
    runtime = get_rag_runtime()
    return {"health": runtime.health().model_dump(mode="json"), "index": runtime.indexer.status()}


@router.post("/rag/knowledge/reindex")
def rag_reindex(
    payload: RagReindexRequest,
    principal: RequireRagManage,
    session: DatabaseSession,
) -> dict:
    result = get_rag_runtime().indexer.index(session, force=payload.force)
    ThreatLensPersistenceService(session).record_audit_event(
        actor=principal.username,
        action="rag.knowledge_reindexed",
        entity_type="rag_knowledge",
        entity_id=result.knowledge_version,
        details={
            "status": result.status,
            "force": payload.force,
            "documents_seen": result.documents_seen,
            "documents_added_or_updated": result.documents_added_or_updated,
            "documents_removed": result.documents_removed,
            "chunks_upserted": result.chunks_upserted,
            "chunks_deleted": result.chunks_deleted,
            "indexed_chunks": result.indexed_chunks,
        },
    )
    return result.model_dump(mode="json")


@router.post("/incidents/{incident_uuid}/assistant/query")
def query_incident_assistant(
    incident_uuid: str,
    payload: RagQueryRequest,
    principal: RequireRagQuery,
    session: DatabaseSession,
) -> dict:
    try:
        response = get_rag_runtime().query(
            session,
            incident_uuid=incident_uuid,
            actor=principal.username,
            question=payload.question,
            analysis_mode=payload.analysis_mode,
        )
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": str(error)},
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "invalid_rag_query", "message": str(error)},
        ) from error
    return response.model_dump(mode="json")


@router.get("/incidents/{incident_uuid}/assistant/history")
def incident_assistant_history(
    incident_uuid: str,
    principal: RequireRagQuery,
    session: DatabaseSession,
    limit: int = 50,
) -> dict[str, object]:
    del principal
    try:
        items = get_rag_runtime().history(session, incident_uuid=incident_uuid, limit=limit)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": str(error)},
        ) from error
    return {"items": [item.model_dump(mode="json") for item in items], "count": len(items)}
