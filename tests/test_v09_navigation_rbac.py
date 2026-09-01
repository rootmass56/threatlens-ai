
from api.rbac import ROLE_DEFINITIONS
from app.navigation_policy import allowed_navigation_pages


def _pages(role_name: str) -> set[str]:
    return set(allowed_navigation_pages(ROLE_DEFINITIONS[role_name].permissions))


def test_viewer_navigation_is_read_only() -> None:
    pages = _pages("viewer")

    assert {
        "overview",
        "current_analysis",
        "analysis_history",
        "incident_queue",
        "case_details",
        "rule_catalog",
        "detection_quality",
        "attack_coverage",
        "attack_graph",
        "connector_health",
        "reports",
    }.issubset(pages)
    assert "upload" not in pages
    assert "audit_trail" not in pages
    assert "security_administration" not in pages


def test_analyst_navigation_supports_analysis_without_privileged_audit() -> None:
    pages = _pages("analyst")

    assert "upload" in pages
    assert "audit_trail" not in pages
    assert "security_administration" not in pages


def test_senior_analyst_navigation_supports_cross_case_audit() -> None:
    pages = _pages("senior_analyst")

    assert "upload" in pages
    assert "audit_trail" in pages
    assert "security_administration" not in pages


def test_incident_commander_navigation_supports_coordination_and_audit() -> None:
    pages = _pages("incident_commander")

    assert "upload" in pages
    assert "incident_queue" in pages
    assert "case_details" in pages
    assert "audit_trail" in pages
    assert "security_administration" not in pages


def test_rule_engineer_navigation_supports_detection_governance_without_ingestion() -> None:
    pages = _pages("rule_engineer")

    assert "rule_catalog" in pages
    assert "detection_quality" in pages
    assert "attack_coverage" in pages
    assert "audit_trail" in pages
    assert "rag_admin" in pages
    assert "upload" not in pages
    assert "security_administration" not in pages


def test_administrator_can_access_every_page() -> None:
    pages = _pages("administrator")

    assert pages == {
        "overview",
        "upload",
        "current_analysis",
        "analysis_history",
        "incident_queue",
        "case_details",
        "audit_trail",
        "rule_catalog",
        "detection_quality",
        "attack_coverage",
        "attack_graph",
        "connector_health",
        "reports",
        "rag_admin",
        "security_administration",
    }
