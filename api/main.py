
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.config import SecuritySettings, get_security_settings
from api.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from api.routes import advanced_soc, analyses, auth, catalog, incidents, jobs, rag, reports, system, users
from api.version import THREATLENS_VERSION

LOGGER = logging.getLogger("threatlens.api")


def _error_payload(
    request: Request,
    *,
    code: str,
    message: str,
    details: Any = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    if details is not None:
        payload["details"] = details
    return {"error": payload}



def _install_openapi_security_contract(app: FastAPI) -> None:
    """Expose the machine-ingestion credential in the OpenAPI security contract."""

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        security_schemes = schema.setdefault("components", {}).setdefault(
            "securitySchemes", {}
        )
        security_schemes["ThreatLensIngestKey"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-ThreatLens-Ingest-Key",
            "description": (
                "Per-source machine credential for receipt-first telemetry ingestion. "
                "ThreatLens stores only the SHA-256 credential hash."
            ),
        }

        realtime = (
            schema.get("paths", {})
            .get("/api/v1/ingest/realtime", {})
            .get("post")
        )
        if isinstance(realtime, dict):
            realtime["security"] = [{"ThreatLensIngestKey": []}]

        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi

def create_app(settings: SecuritySettings | None = None) -> FastAPI:
    settings = settings or get_security_settings()
    app = FastAPI(
        title="ThreatLens AI Security API",
        description=(
            "Authenticated service boundary for multi-source SOC analytics, "
            "case management, governed detections, ATT&CK, attack graphs and "
            "adaptive dual-model grounded RAG investigation, real-time telemetry, threat intelligence, threat hunting, response playbooks and detection feedback."
        ),
        version=THREATLENS_VERSION,
        docs_url="/docs" if settings.enable_development_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_development_docs else None,
    )
    app.state.security_settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "Idempotency-Key", "X-ThreatLens-Ingest-Key"],
        expose_headers=[
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "Location",
        ],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)

    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
    app.include_router(users.router, prefix=prefix)
    app.include_router(analyses.router, prefix=prefix)
    app.include_router(incidents.router, prefix=prefix)
    app.include_router(rag.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(advanced_soc.router, prefix=prefix)
    app.include_router(catalog.router, prefix=prefix)
    app.include_router(reports.router, prefix=prefix)
    app.include_router(system.router, prefix=prefix)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": "ThreatLens AI Security API",
            "version": THREATLENS_VERSION,
            "health": "/api/v1/health/live",
        }

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, error: HTTPException):
        detail = error.detail
        code = "http_error"
        message = str(detail)
        details = None
        if isinstance(detail, dict):
            code = str(detail.get("code") or code)
            message = str(detail.get("message") or "Request failed.")
            details = {
                key: value for key, value in detail.items() if key not in {"code", "message"}
            } or None
        return JSONResponse(
            status_code=error.status_code,
            content=_error_payload(
                request,
                code=code,
                message=message,
                details=details,
            ),
            headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        error: RequestValidationError,
    ):
        sanitized = [
            {
                "location": [str(item) for item in issue.get("loc", ())],
                "message": issue.get("msg"),
                "type": issue.get("type"),
            }
            for issue in error.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_error_payload(
                request,
                code="validation_failed",
                message="Request validation failed.",
                details=sanitized,
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, error: Exception):
        LOGGER.exception(
            "Unhandled API error request_id=%s",
            getattr(request.state, "request_id", None),
            exc_info=error,
        )
        return JSONResponse(
            status_code=500,
            content=_error_payload(
                request,
                code="internal_error",
                message="The request could not be completed.",
            ),
        )

    _install_openapi_security_contract(app)
    return app


app = create_app()
