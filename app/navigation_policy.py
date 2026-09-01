from __future__ import annotations

from typing import Final

NAVIGATION_LABELS: Final[dict[str, str]] = {
    "overview": "Overview",
    "upload": "Upload and Analyze",
    "current_analysis": "Current Analysis",
    "analysis_history": "Analysis History",
    "incident_queue": "Incident Queue",
    "case_details": "Case Details",
    "audit_trail": "Audit Trail",
    "rule_catalog": "Rule Catalog",
    "detection_quality": "Detection Quality",
    "attack_coverage": "MITRE ATT&CK Coverage",
    "attack_graph": "Attack Graph Investigation",
    "connector_health": "Connector Health",
    "reports": "Reports",
    "rag_admin": "AI Knowledge Administration",
    "security_administration": "Security Administration",
}

NAVIGATION_PERMISSIONS: Final[dict[str, str]] = {
    "overview": "system:read",
    "upload": "analysis:create",
    "current_analysis": "analysis:read",
    "analysis_history": "analysis:read",
    "incident_queue": "incident:read",
    "case_details": "incident:read",
    "audit_trail": "audit:read",
    "rule_catalog": "rule:read",
    "detection_quality": "rule:read",
    "attack_coverage": "attack:read",
    "attack_graph": "graph:read",
    "connector_health": "system:read",
    "reports": "report:read",
    "rag_admin": "rag:manage",
    "security_administration": "user:read",
}


def allowed_navigation_pages(permissions: set[str] | frozenset[str]) -> list[str]:
    """Return navigation keys authorized by the supplied permission manifest."""

    return [page for page in NAVIGATION_LABELS if NAVIGATION_PERMISSIONS[page] in permissions]
