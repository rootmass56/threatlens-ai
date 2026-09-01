from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_incident_scoped_batch6_navigation_accepts_explicit_context() -> None:
    source = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert "next === 'caseops'" in source
    assert "next === 'response'" in source
    assert "next === 'graphintel'" in source
    assert "<CaseOperationsPage session={session} incidentId={incidentId} navigate={navigate} />" in source


def test_case_details_links_case_operations_with_selected_incident() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "IncidentsPage.tsx").read_text(encoding="utf-8")
    assert "navigate('caseops', selected)" in source
    assert ">Case Operations</button>" in source


def test_case_operations_exposes_authoritative_selector_and_custody() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "AdvancedSocPages.tsx").read_text(encoding="utf-8")
    assert "Authoritative incident context" in source
    assert "The retained incident context is stale or unavailable" in source
    assert "Registered evidence" in source
    assert "EvidenceCustodyCard" in source
    assert "/api/v1/evidence/${encodeURIComponent(evidenceUuid)}/custody" in source
    assert "hash_verified" in source
    assert "navigate('response',incidentId)" in source
