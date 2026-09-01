from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.rbac import Permission
from core.case_workflow import ALLOWED_STATUS_TRANSITIONS, CLOSING_STATUSES


@dataclass(frozen=True)
class CaseCapabilities:
    can_update: bool
    can_assign_any: bool
    can_add_note: bool
    can_add_evidence: bool
    status_options: tuple[str, ...]


def case_capabilities(user: dict[str, Any], incident: dict[str, Any]) -> CaseCapabilities:
    """Compute frontend capabilities from the same permission/object rules as the API."""

    permissions = set(user.get("permissions") or [])
    username = str(user.get("username") or "").strip().lower()
    assignee = str(incident.get("assignee") or "").strip().lower()

    can_update_any = Permission.INCIDENT_UPDATE_ANY in permissions
    can_update_self = Permission.INCIDENT_UPDATE_SELF in permissions
    can_update = can_update_any or (can_update_self and (not assignee or assignee == username))
    can_assign_any = Permission.INCIDENT_ASSIGN in permissions

    current_status = str(incident.get("status") or "open").strip().lower()
    candidates = list(ALLOWED_STATUS_TRANSITIONS.get(current_status, frozenset({current_status})))
    if Permission.INCIDENT_CLOSE not in permissions:
        candidates = [status for status in candidates if status not in CLOSING_STATUSES]
    if current_status not in candidates:
        candidates.insert(0, current_status)

    return CaseCapabilities(
        can_update=can_update,
        can_assign_any=can_assign_any,
        can_add_note=can_update and Permission.NOTE_CREATE in permissions,
        can_add_evidence=can_update and Permission.EVIDENCE_CREATE in permissions,
        status_options=tuple(candidates),
    )
