
from __future__ import annotations

from dataclasses import dataclass
from typing import Final


class Permission:
    ANALYSIS_READ = "analysis:read"
    ANALYSIS_CREATE = "analysis:create"
    INCIDENT_READ = "incident:read"
    INCIDENT_UPDATE_SELF = "incident:update:self"
    INCIDENT_UPDATE_ANY = "incident:update:any"
    INCIDENT_ASSIGN = "incident:assign"
    INCIDENT_CLOSE = "incident:close"
    NOTE_CREATE = "note:create"
    EVIDENCE_CREATE = "evidence:create"
    AUDIT_READ = "audit:read"
    RULE_READ = "rule:read"
    RULE_MANAGE = "rule:manage"
    ATTACK_READ = "attack:read"
    ATTACK_SYNC = "attack:sync"
    GRAPH_READ = "graph:read"
    REPORT_READ = "report:read"
    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    SYSTEM_READ = "system:read"
    DOCS_VIEW = "docs:view"
    RAG_QUERY = "rag:query"
    RAG_MANAGE = "rag:manage"
    INGEST_READ = "ingest:read"
    INGEST_MANAGE = "ingest:manage"
    INTEL_READ = "intel:read"
    INTEL_MANAGE = "intel:manage"
    HUNT_EXECUTE = "hunt:execute"
    HUNT_MANAGE = "hunt:manage"
    CASE_OPERATE = "case:operate"
    RESPONSE_REQUEST = "response:request"
    RESPONSE_APPROVE = "response:approve"
    RESPONSE_EXECUTE = "response:execute"
    DETECTION_FEEDBACK = "detection:feedback"
    DETECTION_MANAGE = "detection:manage"
    SEARCH_READ = "search:read"


ALL_PERMISSIONS: Final[frozenset[str]] = frozenset(
    value for key, value in Permission.__dict__.items() if key.isupper() and isinstance(value, str)
)


@dataclass(frozen=True)
class RoleDefinition:
    name: str
    description: str
    permissions: frozenset[str]


READ_PERMISSIONS = frozenset(
    {
        Permission.ANALYSIS_READ,
        Permission.INCIDENT_READ,
        Permission.RULE_READ,
        Permission.ATTACK_READ,
        Permission.GRAPH_READ,
        Permission.REPORT_READ,
        Permission.SYSTEM_READ,
        Permission.RAG_QUERY,
        Permission.INGEST_READ,
        Permission.INTEL_READ,
        Permission.SEARCH_READ,
    }
)


INCIDENT_ASSIGNEE_ROLES: Final[frozenset[str]] = frozenset(
    {"analyst", "senior_analyst", "incident_commander", "administrator"}
)


ROLE_DEFINITIONS: Final[dict[str, RoleDefinition]] = {
    "viewer": RoleDefinition(
        "viewer",
        "Read-only SOC dashboard and investigation visibility.",
        READ_PERMISSIONS,
    ),
    "analyst": RoleDefinition(
        "analyst",
        "Triage, evidence registration and self-assigned case workflow.",
        READ_PERMISSIONS
        | {
            Permission.ANALYSIS_CREATE,
            Permission.INCIDENT_UPDATE_SELF,
            Permission.NOTE_CREATE,
            Permission.EVIDENCE_CREATE,
            Permission.HUNT_EXECUTE,
            Permission.CASE_OPERATE,
            Permission.RESPONSE_REQUEST,
            Permission.DETECTION_FEEDBACK,
        },
    ),
    "senior_analyst": RoleDefinition(
        "senior_analyst",
        "Cross-case investigation, workflow control and audit review.",
        READ_PERMISSIONS
        | {
            Permission.ANALYSIS_CREATE,
            Permission.INCIDENT_UPDATE_SELF,
            Permission.INCIDENT_UPDATE_ANY,
            Permission.INCIDENT_ASSIGN,
            Permission.NOTE_CREATE,
            Permission.EVIDENCE_CREATE,
            Permission.AUDIT_READ,
            Permission.HUNT_EXECUTE,
            Permission.HUNT_MANAGE,
            Permission.CASE_OPERATE,
            Permission.RESPONSE_REQUEST,
            Permission.RESPONSE_APPROVE,
            Permission.RESPONSE_EXECUTE,
            Permission.DETECTION_FEEDBACK,
        },
    ),
    "incident_commander": RoleDefinition(
        "incident_commander",
        "Full incident coordination, assignment and closure authority.",
        READ_PERMISSIONS
        | {
            Permission.ANALYSIS_CREATE,
            Permission.INCIDENT_UPDATE_SELF,
            Permission.INCIDENT_UPDATE_ANY,
            Permission.INCIDENT_ASSIGN,
            Permission.INCIDENT_CLOSE,
            Permission.NOTE_CREATE,
            Permission.EVIDENCE_CREATE,
            Permission.AUDIT_READ,
            Permission.HUNT_EXECUTE,
            Permission.HUNT_MANAGE,
            Permission.CASE_OPERATE,
            Permission.RESPONSE_REQUEST,
            Permission.RESPONSE_APPROVE,
            Permission.RESPONSE_EXECUTE,
            Permission.DETECTION_FEEDBACK,
        },
    ),
    "rule_engineer": RoleDefinition(
        "rule_engineer",
        "Detection-catalogue and ATT&CK synchronization authority.",
        READ_PERMISSIONS
        | {
            Permission.RULE_MANAGE,
            Permission.ATTACK_SYNC,
            Permission.AUDIT_READ,
            Permission.RAG_MANAGE,
            Permission.INGEST_MANAGE,
            Permission.INTEL_MANAGE,
            Permission.HUNT_EXECUTE,
            Permission.HUNT_MANAGE,
            Permission.DETECTION_FEEDBACK,
            Permission.DETECTION_MANAGE,
        },
    ),
    "administrator": RoleDefinition(
        "administrator",
        "Complete platform security and administration authority.",
        ALL_PERMISSIONS,
    ),
}


def permissions_for_roles(role_names: set[str] | frozenset[str]) -> frozenset[str]:
    permissions: set[str] = set()
    for role_name in role_names:
        role = ROLE_DEFINITIONS.get(role_name)
        if role is not None:
            permissions.update(role.permissions)
    return frozenset(permissions)
