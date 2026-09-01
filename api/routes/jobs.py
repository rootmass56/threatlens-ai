
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Response, status

from api.dependencies import DatabaseSession, RequireRagQuery
from api.schemas import RagQueryRequest
from jobs.config import get_job_settings
from jobs.models import AiJobStatus
from jobs.queue import QueueUnavailable, RedisJobQueue
from jobs.service import AiJobService, JobCapacityExceeded
from rag.config import get_rag_settings

router = APIRouter(tags=["ai-jobs"])


def _queue_delivery(job_uuid: str, session: DatabaseSession) -> str:
    settings = get_job_settings()
    service = AiJobService(session, settings)
    job = service.get(job_uuid)
    if job is None:
        return "missing"
    try:
        queued = RedisJobQueue(settings).enqueue(job_uuid)
        service.mark_enqueued(job)
        session.commit()
        return "enqueued" if queued else "already_enqueued"
    except QueueUnavailable:
        service.mark_queue_pending(job)
        session.commit()
        return "pending_redis_recovery"


@router.get("/assistant/jobs/health")
def assistant_job_health(principal: RequireRagQuery) -> dict[str, object]:
    del principal
    settings = get_job_settings()
    if not settings.enabled:
        return {
            "enabled": False,
            "queue": settings.queue_name,
            "reachable": False,
            "pending": 0,
            "workers": 0,
            "detail": "Asynchronous jobs are disabled in this runtime profile.",
        }
    snapshot = RedisJobQueue(settings).snapshot()
    return {
        "enabled": True,
        "queue": settings.queue_name,
        "reachable": snapshot.reachable,
        "pending": snapshot.pending,
        "workers": snapshot.workers,
        "detail": snapshot.detail,
    }


@router.post(
    "/incidents/{incident_uuid}/assistant/jobs",
    status_code=status.HTTP_202_ACCEPTED,
)
def create_assistant_job(
    incident_uuid: str,
    payload: RagQueryRequest,
    principal: RequireRagQuery,
    session: DatabaseSession,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, object]:
    settings = get_job_settings()
    if not settings.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "async_jobs_disabled",
                "message": "Durable AI investigation jobs are disabled in this runtime profile.",
            },
        )
    service = AiJobService(session, settings)
    try:
        job, created = service.create(
            incident_uuid=incident_uuid,
            actor=principal.username,
            question=payload.question,
            analysis_mode=payload.analysis_mode,
            idempotency_key=idempotency_key,
            max_question_chars=get_rag_settings().max_question_chars,
        )
        session.commit()
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": str(error)},
        ) from error
    except JobCapacityExceeded as error:
        response.headers["Retry-After"] = "30"
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "ai_job_capacity_exceeded", "message": str(error)},
            headers={"Retry-After": "30"},
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT if "Idempotency-Key" in str(error) else 422,
            detail={"code": "invalid_ai_job", "message": str(error)},
        ) from error

    delivery = _queue_delivery(job.job_uuid, session) if created else job.queue_delivery_state
    current = service.get(job.job_uuid) or job
    response.headers["Location"] = f"/api/v1/assistant/jobs/{job.job_uuid}"
    payload_out = service.serialize(current)
    payload_out["created"] = created
    payload_out["queue_delivery"] = delivery
    return payload_out


@router.get("/assistant/jobs/{job_uuid}")
def get_assistant_job(
    job_uuid: str,
    principal: RequireRagQuery,
    session: DatabaseSession,
) -> dict[str, object]:
    del principal
    service = AiJobService(session, get_job_settings())
    job = service.get(job_uuid)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ai_job_not_found", "message": "AI investigation job was not found."},
        )
    return service.serialize(job)


@router.get("/incidents/{incident_uuid}/assistant/jobs")
def list_assistant_jobs(
    incident_uuid: str,
    principal: RequireRagQuery,
    session: DatabaseSession,
    limit: int = 50,
) -> dict[str, object]:
    del principal
    service = AiJobService(session, get_job_settings())
    try:
        jobs = service.list_for_incident(incident_uuid, limit=limit)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": str(error)},
        ) from error
    return {"items": [service.serialize(job) for job in jobs], "count": len(jobs)}


@router.post("/assistant/jobs/{job_uuid}/cancel")
def cancel_assistant_job(
    job_uuid: str,
    principal: RequireRagQuery,
    session: DatabaseSession,
) -> dict[str, object]:
    service = AiJobService(session, get_job_settings())
    job = service.get(job_uuid)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ai_job_not_found", "message": "AI investigation job was not found."},
        )
    if job.status == AiJobStatus.RUNNING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "ai_job_already_running",
                "message": (
                    "This local-model job is already running and cannot be hard-cancelled safely. "
                    "Queued jobs can be cancelled before execution."
                ),
            },
        )
    service.cancel(job, actor=principal.username)
    session.commit()
    return service.serialize(job)
