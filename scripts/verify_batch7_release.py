from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault(
    "THREATLENS_JWT_SECRET", "batch7-static-release-secret-that-is-long-enough-123456789"
)

from api.main import app
from api.version import THREATLENS_VERSION
from core.connectors import build_default_connector_registry
from core.rules.fixtures import RuleFixtureRunner
from core.rules.loader import RuleLoader
from database.base import Base


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit(message)


def main() -> None:
    require(THREATLENS_VERSION == "0.14.0", f"Expected v0.14.0, got {THREATLENS_VERSION}")

    connector_ids = build_default_connector_registry().connector_ids()
    require(
        connector_ids
        == [
            "entra_id",
            "linux_auth",
            "suricata_eve",
            "syslog_rfc",
            "windows_security",
            "windows_sysmon",
            "zeek",
        ],
        f"Connector set changed: {connector_ids}",
    )

    rules = RuleLoader(ROOT / "rules").validation_report()
    require(rules.valid, str(rules.issues))
    require(len(rules.rules) == 46, f"Expected 46 governed rules, got {len(rules.rules)}")
    fixtures = RuleFixtureRunner(ROOT / "rules").run()
    require(fixtures.passed, "Governed rule fixtures failed.")
    require(fixtures.passed_count == 138, f"Expected 138 fixtures, got {fixtures.passed_count}")

    batch6_tables = {
        "ingestion_sources",
        "realtime_ingress_events",
        "threat_intel_feeds",
        "threat_indicators",
        "threat_intel_hits",
        "saved_hunts",
        "hunt_executions",
        "incident_case_profiles",
        "incident_tasks",
        "incident_handoffs",
        "evidence_custody_events",
        "response_playbooks",
        "response_executions",
        "detection_feedback",
        "detection_tunings",
    }
    require(batch6_tables <= set(Base.metadata.tables), "Batch-6 persistence contract regressed.")

    schema = app.openapi()
    paths = set(schema.get("paths", {}))
    require("/api/v1/system/observability" in paths, "Protected observability API is missing.")
    require("/internal/metrics" not in paths, "Internal metrics endpoint leaked into OpenAPI.")

    migration = (ROOT / "migrations/versions/b7f1c2d30001_batch7_operational_indexes.py").read_text(
        encoding="utf-8"
    )
    require('revision: str = "b7f1c2d30001"' in migration, "Batch-7 migration revision missing.")
    require('down_revision: str | None = "f6a6c0b60001"' in migration, "Migration chain invalid.")

    compose = (ROOT / "compose.batch7.yml").read_text(encoding="utf-8")
    for marker in (
        "prometheus:",
        "grafana:",
        "postgres_exporter:",
        "redis_exporter:",
        "no-new-privileges:true",
        'cap_drop: ["ALL"]',
        '127.0.0.1:8080:8080',
        '127.0.0.1:9090:9090',
        '127.0.0.1:3000:3000',
    ):
        require(marker in compose, f"Batch-7 Compose marker missing: {marker}")

    startup = (ROOT / "scripts/start_production.sh").read_text(encoding="utf-8")
    for marker in ("--no-server-header", "--no-access-log", "--limit-concurrency", "--backlog"):
        require(marker in startup, f"Uvicorn hardening marker missing: {marker}")

    for path in (
        "scripts/backup_batch7.ps1",
        "scripts/restore_batch7_smoke.ps1",
        "scripts/MIGRATE_BATCH6_DATA_TO_BATCH7.ps1",
        "ops/load/batch7_load.py",
        "ops/db/performance_audit.py",
        "ops/security/batch7_security_audit.py",
        ".github/workflows/batch7-ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/batch7-ghcr.yml",
        "BATCH7_ACCEPTANCE_CHECKLIST.md",
    ):
        require((ROOT / path).exists(), f"Batch-7 release asset missing: {path}")

    baseline = json.loads((ROOT / "config/dependency_security_baseline.json").read_text())
    require(baseline["release"] == "0.14.0", "Dependency baseline is not v0.14.0.")
    direct = sum(len(baseline[name]) for name in ("build", "runtime", "development"))
    require(direct == 27, f"Expected 27 reviewed direct dependencies, got {direct}")
    require(baseline["runtime"].get("redis") == "6.4.0", "Redis 6.4.0 baseline missing.")

    sbom = json.loads((ROOT / "sbom/source-dependencies-v0.14.0.cdx.json").read_text())
    require(sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.6", "SBOM invalid.")
    require(len(sbom["components"]) == 27, "v0.14 source SBOM component count is not 27.")

    print("=" * 78)
    print("THREATLENS BATCH 7 OPERATIONAL HARDENING RELEASE CONTRACT: PASS")
    print("=" * 78)
    print("Version              :", THREATLENS_VERSION)
    print("Connectors           :", len(connector_ids))
    print("Governed rules       :", len(rules.rules))
    print("Governed fixtures    :", fixtures.passed_count)
    print("Batch-6 tables       :", len(batch6_tables))
    print("Reviewed dependencies:", direct)
    print("Migration head       : b7f1c2d30001")
    print("Batch-7 phases       : 7A through 7H packaged")


if __name__ == "__main__":
    main()
