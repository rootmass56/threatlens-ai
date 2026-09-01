from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "frontend_feature_parity_v0.12.json"
STREAMLIT_PAGES = ROOT / "app" / "pages"
FRONTEND = ROOT / "frontend" / "src"
OPENAPI = ROOT / "docs" / "openapi_v0.12.0.json"

EXPECTED_LEGACY = {
    "overview.py",
    "upload.py",
    "current_analysis.py",
    "analysis_history.py",
    "incident_queue.py",
    "case_details.py",
    "audit_trail.py",
    "rule_catalog.py",
    "detection_quality.py",
    "attack_coverage.py",
    "attack_graph.py",
    "connector_health.py",
    "reports.py",
    "rag_admin.py",
    "security_administration.py",
}

REQUIRED_API_MARKERS = {
    "/api/v1/auth/me",
    "/api/v1/analyses/upload",
    "/api/v1/analyses?limit=1000",
    "/correlation",
    "/api/v1/incidents?limit=1000",
    "/workflow",
    "/evidence",
    "/notes",
    "/assistant/query",
    "/assistant/history",
    "/api/v1/audit?limit=1000",
    "/api/v1/rules/validation",
    "/api/v1/rules/fixtures",
    "/api/v1/rules/quality/records",
    "/api/v1/attack/catalogues",
    "/api/v1/attack/navigator",
    "/api/v1/attack/synchronize",
    "/api/v1/graphs/",
    "/api/v1/connectors/diagnose",
    "/incident.pdf",
    "/api/v1/rag/knowledge/status",
    "/api/v1/rag/knowledge/reindex",
    "/api/v1/users/roles",
    "/api/v1/system/openapi",
    "/api/v1/system/security",
}

REQUIRED_FRONTEND_MARKERS = {
    "CurrentAnalysisPage",
    "AnalysisHistoryPage",
    "AttackGraphPage",
    "source_metadata",
    "analysis_year",
    "sha256Hex(file)",
    "sha256Hex(response.blob)",
    "incident:update:self",
    "incident:update:any",
    "incident:assign",
    "incident:close",
    "rag:manage",
    "attack:sync",
    "user:manage",
    "Save profile / roles / password",
    "threatlens.current.analysis",
    "threatlens.current.incident",
}


def _normalized_openapi_path(marker: str) -> str | None:
    if not marker.startswith("/api/v1/"):
        return None
    return marker.split("?", 1)[0]


def main() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = payload.get("legacy_surfaces") or []
    mapped = {row["streamlit"] for row in rows}
    if mapped != EXPECTED_LEGACY:
        raise SystemExit(
            f"Feature parity manifest mismatch. missing={sorted(EXPECTED_LEGACY - mapped)} "
            f"extra={sorted(mapped - EXPECTED_LEGACY)}"
        )
    invalid = [row for row in rows if row.get("status") not in {"migrated", "superseded"}]
    if invalid:
        raise SystemExit(f"Incomplete legacy surfaces: {invalid}")
    if any(not row.get("capabilities") for row in rows):
        raise SystemExit("Every legacy surface must declare governed capabilities.")

    actual_streamlit = {
        path.name for path in STREAMLIT_PAGES.glob("*.py") if path.name != "__init__.py"
    }
    if actual_streamlit != EXPECTED_LEGACY:
        raise SystemExit(
            "Streamlit surface inventory changed without updating parity governance: "
            f"actual={sorted(actual_streamlit)}"
        )

    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(FRONTEND.rglob("*.ts*")))
    missing_api_markers = sorted(marker for marker in REQUIRED_API_MARKERS if marker not in source)
    if missing_api_markers:
        raise SystemExit(
            "React feature parity is missing API capabilities: " + ", ".join(missing_api_markers)
        )
    missing_frontend_markers = sorted(
        marker for marker in REQUIRED_FRONTEND_MARKERS if marker not in source
    )
    if missing_frontend_markers:
        raise SystemExit(
            "React feature parity is missing workflow/integrity controls: "
            + ", ".join(missing_frontend_markers)
        )

    openapi = json.loads(OPENAPI.read_text(encoding="utf-8"))
    openapi_paths = set(openapi.get("paths") or {})
    missing_contract_paths: list[str] = []
    for marker in REQUIRED_API_MARKERS:
        normalized = _normalized_openapi_path(marker)
        dynamic_markers = (
            "/workflow",
            "/evidence",
            "/notes",
            "/assistant/",
            "/graphs/",
            "/incident.pdf",
            "/correlation",
        )
        if normalized is None or any(token in normalized for token in dynamic_markers):
            continue
        if normalized not in openapi_paths:
            missing_contract_paths.append(normalized)
    if missing_contract_paths:
        raise SystemExit(
            "Feature-parity frontend references API surfaces missing from canonical OpenAPI: "
            + ", ".join(sorted(set(missing_contract_paths)))
        )

    if re.search(r"localhost:8501|streamlit run", source, flags=re.IGNORECASE):
        raise SystemExit("Production React source must not depend on the legacy Streamlit runtime.")

    print(
        "ThreatLens React feature parity verified: "
        f"{len(rows)} legacy analyst surfaces migrated/superseded; "
        f"{len(REQUIRED_API_MARKERS)} governed API markers and "
        f"{len(REQUIRED_FRONTEND_MARKERS)} workflow/integrity controls present."
    )


if __name__ == "__main__":
    main()
