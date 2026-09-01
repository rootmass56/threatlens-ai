
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.dependencies import (
    CurrentPrincipal,
    DatabaseSession,
    RequireAuditRead,
    RequireEvidenceCreate,
    RequireIncidentRead,
    RequireNoteCreate,
)
from api.rbac import INCIDENT_ASSIGNEE_ROLES, Permission
from api.schemas import EvidenceRequest, IncidentWorkflowRequest, InvestigationNoteRequest
from api.security import get_user_by_username
from api.serialization import dataframe_records, json_safe
from app.application_service import ThreatLensApplicationService
from core.case_workflow import CLOSING_STATUSES
from core.concurrency import StripedLockRegistry
from database.exceptions import InvalidIncidentStateError
from database.service import ThreatLensPersistenceService

router = APIRouter(tags=["incidents"])
_INCIDENT_MUTATION_LOCKS = StripedLockRegistry()


def _incident_details_or_404(incident_uuid: str) -> dict:
    details = ThreatLensApplicationService().get_incident_details(incident_uuid)
    if details is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": "Incident was not found."},
        )
    return details


def _can_modify(principal, incident: dict, *, closing: bool = False) -> bool:
    if closing and Permission.INCIDENT_CLOSE not in principal.permissions:
        return False
    if Permission.INCIDENT_UPDATE_ANY in principal.permissions:
        return True
    if Permission.INCIDENT_UPDATE_SELF not in principal.permissions:
        return False
    assignee = (incident.get("assignee") or "").strip().lower()
    return not assignee or assignee == principal.username.lower()


@router.get("/incidents")
def list_incidents(
    principal: RequireIncidentRead,
    status_filter: str | None = None,
    limit: int = 250,
) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_incident_queue(
        status=status_filter,
        limit=min(max(limit, 1), 1000),
    )
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/incidents/{incident_uuid}")
def get_incident(
    incident_uuid: str,
    principal: RequireIncidentRead,
) -> dict[str, object]:
    details = _incident_details_or_404(incident_uuid)
    if Permission.AUDIT_READ not in principal.permissions:
        details = dict(details)
        details["audit"] = []
        details["audit_authorized"] = False
    else:
        details["audit_authorized"] = True
    return json_safe(details)


@router.patch("/incidents/{incident_uuid}/workflow")
def update_workflow(
    incident_uuid: str,
    payload: IncidentWorkflowRequest,
    principal: CurrentPrincipal,
    session: DatabaseSession,
) -> dict[str, object]:
    with _INCIDENT_MUTATION_LOCKS.lock_for(incident_uuid):
        # Authentication has already touched this Session before the route acquires the
        # lock. End that read transaction so this workflow mutation observes the latest
        # committed case state from any request that completed while we were waiting.
        session.rollback()
        result = _update_workflow_locked(
            incident_uuid=incident_uuid,
            payload=payload,
            principal=principal,
            session=session,
        )
        session.commit()
        return result


def _update_workflow_locked(
    *,
    incident_uuid: str,
    payload: IncidentWorkflowRequest,
    principal: CurrentPrincipal,
    session: DatabaseSession,
) -> dict[str, object]:
    persistence = ThreatLensPersistenceService(session)
    details = persistence.get_incident_details(incident_uuid)
    if details is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": "Incident was not found."},
        )
    incident = details["incident"]
    supplied = payload.model_fields_set

    effective_status = (
        payload.status if "status" in supplied else str(incident.get("status") or "open")
    )
    closing = effective_status.lower() in CLOSING_STATUSES
    if not _can_modify(principal, incident, closing=closing):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "incident_object_access_denied",
                "message": "The user cannot modify this incident object.",
            },
        )

    current_assignee = (incident.get("assignee") or "").strip().lower()
    assignee_was_supplied = "assignee" in supplied
    requested_assignee = (
        (payload.assignee or "").strip().lower() if assignee_was_supplied else current_assignee
    )

    if requested_assignee != current_assignee:
        assigning_to_self = requested_assignee == principal.username.lower()
        if not assigning_to_self and Permission.INCIDENT_ASSIGN not in principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "assignment_permission_denied",
                    "message": "The role cannot assign or unassign incidents for another analyst.",
                },
            )

        if requested_assignee:
            target = get_user_by_username(session, requested_assignee)
            if target is None or not target.is_active:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "code": "invalid_incident_assignee",
                        "message": "Incident assignee must be an active ThreatLens user.",
                    },
                )
            target_roles = {role.name for role in target.roles}
            if not target_roles & INCIDENT_ASSIGNEE_ROLES:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "code": "ineligible_incident_assignee",
                        "message": (
                            "Incident assignee must have an investigator-eligible role: "
                            "analyst, senior_analyst, incident_commander, or administrator."
                        ),
                    },
                )
            requested_assignee = target.username

    effective_priority = (
        payload.priority if "priority" in supplied else str(incident.get("priority") or "P3")
    )

    try:
        persistence.update_incident_workflow(
            incident_uuid=incident_uuid,
            status=effective_status,
            assignee=(requested_assignee or None),
            priority=effective_priority,
            actor=principal.username,
        )
        session.flush()
    except InvalidIncidentStateError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "workflow_update_failed", "message": str(error)},
        ) from error

    updated = persistence.get_incident_details(incident_uuid)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "incident_not_found", "message": "Incident was not found."},
        )
    return json_safe(updated)


@router.post("/incidents/{incident_uuid}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    incident_uuid: str,
    payload: InvestigationNoteRequest,
    principal: RequireNoteCreate,
) -> dict[str, str]:
    with _INCIDENT_MUTATION_LOCKS.lock_for(incident_uuid):
        details = _incident_details_or_404(incident_uuid)
        if not _can_modify(principal, details["incident"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "incident_object_access_denied",
                    "message": "Case access denied.",
                },
            )
        note_id = ThreatLensApplicationService().add_incident_note(
            incident_uuid=incident_uuid,
            author=principal.username,
            note=payload.note,
        )
        return {"note_id": note_id}


@router.post("/incidents/{incident_uuid}/evidence", status_code=status.HTTP_201_CREATED)
def add_evidence(
    incident_uuid: str,
    payload: EvidenceRequest,
    principal: RequireEvidenceCreate,
) -> dict[str, str]:
    with _INCIDENT_MUTATION_LOCKS.lock_for(incident_uuid):
        details = _incident_details_or_404(incident_uuid)
        if not _can_modify(principal, details["incident"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "incident_object_access_denied",
                    "message": "Case access denied.",
                },
            )
        evidence_uuid = ThreatLensApplicationService().register_incident_evidence(
            incident_uuid=incident_uuid,
            evidence_type=payload.evidence_type,
            description=payload.description,
            source_reference=payload.source_reference,
            sha256=payload.sha256,
            actor=principal.username,
        )
        return {"evidence_uuid": evidence_uuid}


@router.get("/audit")
def audit_logs(
    principal: RequireAuditRead,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 500,
) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_audit_logs(
        entity_type=entity_type,
        entity_id=entity_id,
        limit=min(max(limit, 1), 1000),
    )
    return {"items": dataframe_records(frame), "count": len(frame)}
