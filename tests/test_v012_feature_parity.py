
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from database.base import Base
from database.models import AnalysisSessionModel, AuditLogModel, SecurityRoleModel
from scripts.migrate_v0111_operational_data import (
    EXPECTED_REVISION,
    OPERATIONAL_TABLES,
    PRESERVED_TARGET_TABLES,
    migrate,
)

ROOT = Path(__file__).resolve().parents[1]
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


def _empty_database(path: Path) -> None:
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(engine)
    engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        connection.execute(
            "INSERT INTO alembic_version(version_num) VALUES (?)",
            (EXPECTED_REVISION,),
        )
        connection.commit()


def test_v012_react_feature_parity_manifest_covers_every_streamlit_surface() -> None:
    payload = json.loads(
        (ROOT / "config" / "frontend_feature_parity_v0.12.json").read_text(encoding="utf-8")
    )
    rows = payload["legacy_surfaces"]
    assert {row["streamlit"] for row in rows} == EXPECTED_LEGACY
    assert all(row["status"] in {"migrated", "superseded"} for row in rows)
    assert all(row["capabilities"] for row in rows)
    assert payload["schema"] == "threatlens-react-feature-parity-1.1"
    assert len(payload["production_only_improvements"]) >= 4


def test_v012_react_parity_source_contains_legacy_and_security_boundaries() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "frontend" / "src").rglob("*.ts*"))
    )
    for marker in (
        "/api/v1/auth/me",
        "/api/v1/analyses/upload",
        "/assistant/jobs",
        "/assistant/history",
        "/api/v1/rules/fixtures",
        "/api/v1/attack/navigator",
        "/api/v1/graphs/",
        "/api/v1/connectors/diagnose",
        "/incident.pdf",
        "/api/v1/users/roles",
        "/api/v1/system/openapi",
        "CurrentAnalysisPage",
        "AttackGraphPage",
        "incident:update:self",
        "incident:assign",
        "rag:manage",
        "attack:sync",
        "user:manage",
        "sha256Hex(file)",
        "sha256Hex(response.blob)",
        "window.history.pushState",
        "window.history.replaceState",
        "window.addEventListener('popstate'",
        "browserRoute",
        "readBrowserRoute",
        "function goBack()",
        "Investigation workflow",
        'rowActionLabel="Open analysis →"',
        'rowActionLabel="Open case →"',
        "← Incident Queue",
        "← Previous case",
        "Next case →",
        "rowActionLabel?: string | ((row: Json) => string)",
        'className="row-action"',
        "refreshInFlight",
        "accessTokenUsed",
        "session.accessToken === accessTokenUsed",
        "if (!loadSession()) setSession(null)",
    ):
        assert marker in source
    assert "localhost:8501" not in source
    assert "streamlit run" not in source.lower()

    from scripts.release_inventory import is_release_relative_path

    assert not is_release_relative_path("data/uat/feature-parity-uat-test.json")
    assert not is_release_relative_path("frontend/tsconfig.app.tsbuildinfo")
    assert is_release_relative_path("frontend/package-lock.json")


def test_v012_react_upload_uses_full_fastapi_multisource_contract() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "AnalysesPage.tsx").read_text(encoding="utf-8")
    assert "form.append('analysis_name'" in source
    assert "form.append('allow_duplicate'" in source
    assert "form.append('source_metadata'" in source
    assert "analysis_year" in source
    assert "/api/v1/connectors/diagnose" in source
    assert "max_file_bytes" in source
    assert "max_batch_bytes" in source
    assert "form.append('connector_id'" not in source


def test_v012_operational_migration_and_incident_audit_enforce_security_boundaries() -> None:
    assert "user_accounts" not in OPERATIONAL_TABLES
    assert "refresh_tokens" not in OPERATIONAL_TABLES
    assert "security_roles" not in OPERATIONAL_TABLES
    assert {"security_roles", "user_accounts", "refresh_tokens", "login_attempts"} <= set(
        PRESERVED_TARGET_TABLES
    )
    migration_source = (ROOT / "scripts" / "migrate_v0111_operational_data.py").read_text(
        encoding="utf-8"
    )
    assert "PRAGMA integrity_check" in migration_source
    assert "pre-v0111-migration" in migration_source
    assert "BEGIN IMMEDIATE" in migration_source
    incident_route = (ROOT / "api" / "routes" / "incidents.py").read_text(encoding="utf-8")
    assert "Permission.AUDIT_READ not in principal.permissions" in incident_route
    assert 'details["audit"] = []' in incident_route


def test_v012_operational_migration_dry_run_and_apply_preserve_security(tmp_path: Path) -> None:
    source = tmp_path / "v0111.db"
    target = tmp_path / "v012.db"
    _empty_database(source)
    _empty_database(target)

    source_engine = create_engine(f"sqlite:///{source.as_posix()}")
    with Session(source_engine) as session:
        session.add(
            AnalysisSessionModel(
                id=41,
                session_uuid="11111111-1111-4111-8111-111111111111",
                name="Legacy investigation",
                status="completed",
                source_type="windows_security",
                schema_version="1.0.0",
                rule_catalog_version="0.11.1",
                analysis_context_json={},
                parser_version="0.11.1",
                engine_version="0.11.1",
                total_events=0,
                total_alerts=0,
                total_incidents=0,
                total_quarantined=0,
                parse_success_rate=100.0,
                parser_statistics_json={},
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            AuditLogModel(
                actor="legacy-analyst",
                action="analysis.completed",
                entity_type="analysis_session",
                entity_id="11111111-1111-4111-8111-111111111111",
                details_json={"source": "v0.11.1"},
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    source_engine.dispose()

    target_engine = create_engine(f"sqlite:///{target.as_posix()}")
    with Session(target_engine) as session:
        session.add(
            SecurityRoleModel(
                id=77,
                name="v012_security_sentinel",
                description="Must survive operational migration",
                permissions_json=["system:read"],
                is_system=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        )
        session.commit()
    target_engine.dispose()

    dry_run = migrate(
        source_path=source,
        target_path=target,
        replace_operational_data=False,
        dry_run=True,
    )
    assert dry_run["status"] == "dry_run"
    assert dry_run["source_revision"] == EXPECTED_REVISION
    assert dry_run["target_revision"] == EXPECTED_REVISION
    assert dry_run["source_integrity"] == "ok"
    assert dry_run["target_integrity"] == "ok"
    assert dry_run["backup_path"] is None
    assert dry_run["source_counts"]["analysis_sessions"] == 1

    applied = migrate(
        source_path=source,
        target_path=target,
        replace_operational_data=False,
        dry_run=False,
    )
    assert applied["status"] == "migrated"
    assert applied["post_migration_integrity"] == "ok"
    assert applied["copied"]["analysis_sessions"] == 1
    assert applied["copied"]["audit_logs"] == 1
    backup = Path(str(applied["backup_path"]))
    assert backup.is_file()

    verify_engine = create_engine(f"sqlite:///{target.as_posix()}")
    with Session(verify_engine) as session:
        migrated_analysis = session.scalar(
            select(AnalysisSessionModel).where(AnalysisSessionModel.id == 41)
        )
        preserved_role = session.scalar(select(SecurityRoleModel).where(SecurityRoleModel.id == 77))
        migrated_audit = session.scalar(
            select(AuditLogModel).where(AuditLogModel.actor == "legacy-analyst")
        )
        assert migrated_analysis is not None
        assert migrated_analysis.name == "Legacy investigation"
        assert preserved_role is not None
        assert preserved_role.name == "v012_security_sentinel"
        assert migrated_audit is not None
    verify_engine.dispose()
