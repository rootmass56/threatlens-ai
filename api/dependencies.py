
from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from api.config import SecuritySettings
from api.rbac import Permission
from api.security import InvalidTokenError, Principal, principal_from_access_token
from database.session import SessionLocal

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_database_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


DatabaseSession = Annotated[Session, Depends(get_database_session, scope="function")]


def get_request_security_settings(request: Request) -> SecuritySettings:
    """Return the immutable settings bound to this FastAPI application instance."""

    return request.app.state.security_settings


Settings = Annotated[SecuritySettings, Depends(get_request_security_settings)]


def get_current_principal(
    session: DatabaseSession,
    settings: Settings,
    token: Annotated[str, Depends(_oauth2_scheme)],
) -> Principal:
    try:
        return principal_from_access_token(session, token=token, settings=settings)
    except InvalidTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_token", "message": str(error)},
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_permissions(*required: str, any_of: bool = False) -> Callable:
    required_set = frozenset(required)

    def dependency(principal: CurrentPrincipal) -> Principal:
        if any_of:
            allowed = bool(principal.permissions & required_set)
        else:
            allowed = required_set.issubset(principal.permissions)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "permission_denied",
                    "message": "The authenticated role does not permit this operation.",
                    "required_permissions": sorted(required_set),
                },
            )
        return principal

    return dependency


RequireAnalysisRead = Annotated[Principal, Depends(require_permissions(Permission.ANALYSIS_READ))]
RequireAnalysisCreate = Annotated[
    Principal, Depends(require_permissions(Permission.ANALYSIS_CREATE))
]
RequireIncidentRead = Annotated[Principal, Depends(require_permissions(Permission.INCIDENT_READ))]
RequireRuleRead = Annotated[Principal, Depends(require_permissions(Permission.RULE_READ))]
RequireAttackRead = Annotated[Principal, Depends(require_permissions(Permission.ATTACK_READ))]
RequireGraphRead = Annotated[Principal, Depends(require_permissions(Permission.GRAPH_READ))]
RequireReportRead = Annotated[Principal, Depends(require_permissions(Permission.REPORT_READ))]
RequireAuditRead = Annotated[Principal, Depends(require_permissions(Permission.AUDIT_READ))]
RequireUserRead = Annotated[Principal, Depends(require_permissions(Permission.USER_READ))]
RequireUserManage = Annotated[Principal, Depends(require_permissions(Permission.USER_MANAGE))]
RequireSystemRead = Annotated[Principal, Depends(require_permissions(Permission.SYSTEM_READ))]
RequireAttackSync = Annotated[Principal, Depends(require_permissions(Permission.ATTACK_SYNC))]
RequireNoteCreate = Annotated[Principal, Depends(require_permissions(Permission.NOTE_CREATE))]
RequireEvidenceCreate = Annotated[
    Principal, Depends(require_permissions(Permission.EVIDENCE_CREATE))
]
RequireDocsView = Annotated[Principal, Depends(require_permissions(Permission.DOCS_VIEW))]
RequireRagQuery = Annotated[
    Principal,
    Depends(require_permissions(Permission.RAG_QUERY, Permission.INCIDENT_READ)),
]
RequireRagManage = Annotated[Principal, Depends(require_permissions(Permission.RAG_MANAGE))]


def request_context(request: Request) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "source_ip": request.client.host if request.client else None,
        "client_fingerprint": request.headers.get("User-Agent"),
    }

# Batch 6 advanced SOC authorization boundaries.
RequireIngestRead = Annotated[Principal, Depends(require_permissions(Permission.INGEST_READ))]
RequireIngestManage = Annotated[Principal, Depends(require_permissions(Permission.INGEST_MANAGE))]
RequireIntelRead = Annotated[Principal, Depends(require_permissions(Permission.INTEL_READ))]
RequireIntelManage = Annotated[Principal, Depends(require_permissions(Permission.INTEL_MANAGE))]
RequireHuntExecute = Annotated[Principal, Depends(require_permissions(Permission.HUNT_EXECUTE))]
RequireHuntManage = Annotated[Principal, Depends(require_permissions(Permission.HUNT_MANAGE))]
RequireCaseOperate = Annotated[
    Principal, Depends(require_permissions(Permission.CASE_OPERATE, Permission.INCIDENT_READ))
]
RequireResponseRequest = Annotated[
    Principal, Depends(require_permissions(Permission.RESPONSE_REQUEST, Permission.INCIDENT_READ))
]
RequireResponseApprove = Annotated[Principal, Depends(require_permissions(Permission.RESPONSE_APPROVE))]
RequireResponseExecute = Annotated[Principal, Depends(require_permissions(Permission.RESPONSE_EXECUTE))]
RequireDetectionFeedback = Annotated[Principal, Depends(require_permissions(Permission.DETECTION_FEEDBACK))]
RequireDetectionManage = Annotated[Principal, Depends(require_permissions(Permission.DETECTION_MANAGE))]
RequireSearchRead = Annotated[Principal, Depends(require_permissions(Permission.SEARCH_READ))]
