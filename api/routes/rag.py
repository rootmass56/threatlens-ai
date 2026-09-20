
from __future__ import annotations

import logging
from datetime import UTC, datetime
from threading import RLock

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from api.dependencies import DatabaseSession, RequireRagManage, RequireRagQuery
from api.schemas import RagQueryRequest, RagReindexRequest
from database.service import ThreatLensPersistenceService
from database.session import SessionLocal
from rag.runtime import get_rag_runtime

router = APIRouter(tags=["rag"])
LOGGER = logging.getLogger("threatlens.rag.reindex")
_REINDEX_STATE_LOCK = RLock()
_REINDEX_STATE: dict[str, object] = {
    "state": "idle",
    "force": None,
    "started_utc": None,
    "completed_utc": None,
    "result_status": None,
    "indexed_chunks": None,
    "detail": None,
}


def _reindex_snapshot() -> dict[str, object]:
    with _REINDEX_STATE_LOCK:
        return dict(_REINDEX_STATE)


def _reserve_reindex(*, force: bool) -> bool:
    with _REINDEX_STATE_LOCK:
        if _REINDEX_STATE["state"] == "running":
            return False
        _REINDEX_STATE.update(
            {
                "state": "running",
                "force": force,
                "started_utc": datetime.now(UTC).isoformat(),
                "completed_utc": None,
                "result_status": None,
                "indexed_chunks": None,
                "detail": "Governed knowledge re-index is running in the background.",
            }
        )
        return True


def _finish_reindex(
    *,
    state: str,
    result_status: str | None = None,
    indexed_chunks: int | None = None,
    detail: str | None = None,
) -> None:
    with _REINDEX_STATE_LOCK:
        _REINDEX_STATE.update(
            {
                "state": state,
                "completed_utc": datetime.now(UTC).isoformat(),
                "result_status": result_status,
                "indexed_chunks": indexed_chunks,
                "detail": detail,
            }
        )


def _run_rag_reindex(*, force: bool, actor: str) -> None:
    session = SessionLocal()
    try:
        result = get_rag_runtime().indexer.index(session, force=force)
        ThreatLensPersistenceService(session).record_audit_event(
            actor=actor,
            action="rag.knowledge_reindexed",
            entity_type="rag_knowledge",
            entity_id=result.knowledge_version,
            details={
                "status": result.status,
                "force": force,
                "documents_seen": result.documents_seen,
                "documents_added_or_updated": result.documents_added_or_updated,
                "documents_removed": result.documents_removed,
                "chunks_upserted": result.chunks_upserted,
                "chunks_deleted": result.chunks_deleted,
                "indexed_chunks": result.indexed_chunks,
            },
        )
        session.commit()
    except Exception:
        session.rollback()
        LOGGER.exception("Background governed-knowledge re-index failed.")
        _finish_reindex(
            state="failed",
            detail="Knowledge re-index failed. Review the API logs before retrying.",
        )
        return
    finally:
        session.close()

    _finish_reindex(
        state="completed",
        result_status=result.status,
        indexed_chunks=result.indexed_chunks,
        detail="Governed knowledge re-index completed.",
    )


@router.get("/rag/health")
def rag_health(principal: RequireRagQuery) -> dict:
    del principal
    return get_rag_runtime().health().model_dump(mode="json")


@router.get("/rag/knowledge/status")
def rag_knowledge_status(principal: RequireRagQuery) -> dict:
    del principal
    runtime = get_rag_runtime()
    return {
        "health": runtime.health().model_dump(mode="json"),
        "index": runtime.indexer.status(),
        "reindex": _reindex_snapshot(),
    }


@router.post(
    "/rag/knowledge/reindex",
    status_code=status.HTTP_202_ACCEPTED,
)
def rag_reindex(
    payload: RagReindexRequest,
    principal: RequireRagManage,
    background_tasks: BackgroundTasks,
) -> dict[str, object]:
    accepted = _reserve_reindex(force=payload.force)
    if accepted:
        background_tasks.add_task(
            _run_rag_reindex,
            force=payload.force,
            actor=principal.username,
        )
    return {
        "status": "accepted" if accepted else "running",
        "reindex": _reindex_snapshot(),
    }


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
