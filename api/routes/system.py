
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text

from api.dependencies import DatabaseSession, RequireDocsView, RequireSystemRead, Settings
from api.version import THREATLENS_VERSION
from core.observability import METRICS
from database.models import AnalysisSessionModel, UserAccountModel
from jobs.config import get_job_settings
from jobs.queue import RedisJobQueue

router = APIRouter(tags=["system"])


@router.get("/health/live")
def live() -> dict[str, object]:
    return {"status": "ok", "version": THREATLENS_VERSION, "timestamp": datetime.now(UTC)}


@router.get("/health/ready")
def ready(session: DatabaseSession) -> JSONResponse:
    session.execute(text("SELECT 1"))
    jobs = get_job_settings()
    queue: dict[str, object] = {"enabled": jobs.enabled}
    ready_state = True
    if jobs.enabled:
        snapshot = RedisJobQueue(jobs).snapshot()
        queue.update(
            {
                "reachable": snapshot.reachable,
                "pending": snapshot.pending,
                "workers": snapshot.workers,
                "detail": snapshot.detail,
            }
        )
        ready_state = snapshot.reachable and snapshot.workers > 0

    payload = {
        "status": "ready" if ready_state else "degraded",
        "version": THREATLENS_VERSION,
        "database": "reachable",
        "async_jobs": queue,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    return JSONResponse(status_code=200 if ready_state else 503, content=payload)


@router.get("/system/security")
def security_status(
    principal: RequireSystemRead,
    session: DatabaseSession,
    settings: Settings,
) -> dict[str, object]:
    del principal
    return {
        "version": THREATLENS_VERSION,
        "authentication": "OAuth2 password flow with Argon2id and signed JWT",
        "access_token_minutes": settings.access_token_minutes,
        "refresh_token_hours": settings.refresh_token_hours,
        "refresh_rotation": True,
        "account_lockout": {
            "attempts": settings.max_failed_logins,
            "minutes": settings.lockout_minutes,
        },
        "cors_allowlist": list(settings.allowed_origins),
        "trusted_hosts": list(settings.trusted_hosts),
        "development_docs_enabled": settings.enable_development_docs,
        "upload_limits": {
            "max_file_bytes": settings.max_upload_bytes,
            "max_files": settings.max_upload_files,
            "max_batch_bytes": settings.max_upload_bytes * settings.max_upload_files,
        },
        "user_count": session.scalar(select(func.count(UserAccountModel.id))) or 0,
        "analysis_count": session.scalar(select(func.count(AnalysisSessionModel.id))) or 0,
        "async_jobs": {
            "enabled": get_job_settings().enabled,
            "queue": get_job_settings().queue_name,
        },
    }


@router.get("/system/openapi")
def protected_openapi(
    request: Request,
    principal: RequireDocsView,
) -> JSONResponse:
    del principal
    return JSONResponse(request.app.openapi())

@router.get("/system/observability")
def observability_status(
    principal: RequireSystemRead,
    settings: Settings,
) -> dict[str, object]:
    del principal
    job_settings = get_job_settings()
    queue: dict[str, object] = {"enabled": job_settings.enabled}
    if job_settings.enabled:
        try:
            snapshot = RedisJobQueue(job_settings).snapshot()
            queue.update(
                {
                    "reachable": snapshot.reachable,
                    "pending": snapshot.pending,
                    "workers": snapshot.workers,
                    "detail": snapshot.detail,
                }
            )
        except Exception as error:
            queue.update({"reachable": False, "detail": type(error).__name__})
    return {
        "version": THREATLENS_VERSION,
        "structured_logging": settings.structured_logging,
        "log_level": settings.log_level,
        "metrics_enabled": settings.metrics_enabled,
        "slow_request_ms": settings.slow_request_ms,
        "https_only": settings.https_only,
        "max_request_body_bytes": settings.max_request_body_bytes,
        "async_jobs": queue,
        "metrics": METRICS.snapshot(),
    }

