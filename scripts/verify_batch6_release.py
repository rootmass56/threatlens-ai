from __future__ import annotations
import json, os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
os.environ.setdefault("THREATLENS_JWT_SECRET","batch6-static-release-secret-that-is-long-enough-123456789")
from api.main import app
from api.version import THREATLENS_VERSION
from core.connectors import build_default_connector_registry
from core.rules.fixtures import RuleFixtureRunner
from core.rules.loader import RuleLoader
from database.base import Base

def require(v,msg):
    if not v: raise SystemExit(msg)

def main():
    require(THREATLENS_VERSION=="0.13.0", f"Expected v0.13.0, got {THREATLENS_VERSION}")
    ids=build_default_connector_registry().connector_ids()
    require(ids==["entra_id","linux_auth","suricata_eve","syslog_rfc","windows_security","windows_sysmon","zeek"], f"Connector set changed: {ids}")
    report=RuleLoader(ROOT/"rules").validation_report(); require(report.valid, str(report.issues)); require(len(report.rules)==46, f"Expected 46 rules, got {len(report.rules)}")
    fixtures=RuleFixtureRunner(ROOT/"rules").run(); require(fixtures.passed, str([r for r in fixtures.results if not r.passed])); require(fixtures.passed_count==138, f"Expected 138 fixtures, got {fixtures.passed_count}")
    required_tables={"ingestion_sources","realtime_ingress_events","threat_intel_feeds","threat_indicators","threat_intel_hits","saved_hunts","hunt_executions","incident_case_profiles","incident_tasks","incident_handoffs","evidence_custody_events","response_playbooks","response_executions","detection_feedback","detection_tunings"}
    require(required_tables <= set(Base.metadata.tables), "One or more Batch-6 persistence tables are missing.")
    schema=app.openapi(); paths=set(schema.get("paths",{}))
    required_paths={"/api/v1/ingestion/sources","/api/v1/ingest/realtime","/api/v1/intel/feeds","/api/v1/intel/indicators","/api/v1/hunts/execute","/api/v1/hunts/saved","/api/v1/incidents/{incident_uuid}/case-operations","/api/v1/response/playbooks","/api/v1/detections/feedback","/api/v1/detections/tunings","/api/v1/incidents/{incident_uuid}/graph/intelligence","/api/v1/search"}
    require(required_paths <= paths, f"Missing Batch-6 API paths: {sorted(required_paths-paths)}")
    machine=schema["paths"]["/api/v1/ingest/realtime"]["post"]
    require(any(p.get("name")=="X-ThreatLens-Ingest-Key" and p.get("in")=="header" for p in machine.get("parameters",[])), "Machine-auth header missing.")
    migration=(ROOT/"migrations/versions/f6a6c0b60001_batch6_advanced_soc.py").read_text(encoding="utf-8")
    require('revision: str = "f6a6c0b60001"' in migration and 'down_revision: str | None = "e9b5a1300001"' in migration, "Batch-6 migration chain invalid.")
    frontend=(ROOT/"frontend/src/pages/AdvancedSocPages.tsx").read_text(encoding="utf-8")
    for marker in ("RealtimePage","ThreatIntelPage","HuntPage","CaseOperationsPage","ResponsePage","DetectionEngineeringPage","IdentityPage","GraphIntelligencePage"):
        require(f"export function {marker}" in frontend, f"Frontend page missing: {marker}")
    print("="*78); print("THREATLENS BATCH 6 ADVANCED SOC STATIC RELEASE CONTRACT: PASS"); print("="*78)
    print("Version             :",THREATLENS_VERSION); print("Connectors          :",len(ids)); print("Governed rules      :",len(report.rules)); print("Governed fixtures   :",fixtures.passed_count); print("Batch-6 tables      :",len(required_tables)); print("OpenAPI paths       :",len(paths)); print("Advanced SOC modules: 6A through 6H present")
if __name__=="__main__": main()
