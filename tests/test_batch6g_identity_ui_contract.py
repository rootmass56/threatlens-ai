from pathlib import Path


def test_batch6g_identity_page_exposes_live_persisted_evidence() -> None:
    source = Path(
        "frontend/src/pages/AdvancedSocPages.tsx"
    ).read_text(encoding="utf-8")

    markers = (
        "/api/v1/connectors",
        "/api/v1/ingestion/sources",
        "/api/v1/ingestion/recent?limit=250",
        "/api/v1/analyses?limit=250",
        'label="Latest events"',
        'label="Latest alerts"',
        'label="Durable receipts"',
        'title="Latest Entra analysis"',
        'title="Latest Entra durable receipts"',
        'title="Authenticated Entra sources"',
        "analysis_session_uuid",
        "entra_risky_signin",
        "entra_mfa_failure",
        "entra_signin_failure",
        "entra_privileged_role_assignment",
    )

    for marker in markers:
        assert marker in source