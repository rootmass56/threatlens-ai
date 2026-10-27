
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from api.version import THREATLENS_VERSION
from attack.service import AttackCatalogService
from attack.sources import (
    ALL_ATTACK_SOURCES,
    AttackCatalogDownloadError,
    AttackCatalogSource,
    validate_attack_bundle_file,
)
from database.base import Base
from database.models import AttackCatalogVersionModel, RefreshTokenModel, UserAccountModel
from database.session import DEFAULT_DATABASE_URL, resolve_database_url
from tests.test_application_service import application_service as _base_application_service
from tests.test_v09_security_api import auth_header, login
from tests.test_v09_security_api import security_environment as _base_security_environment


@pytest.fixture(name="application_service")
def _application_service_fixture():
    yield from _base_application_service.__wrapped__()


@pytest.fixture(name="security_environment")
def _security_environment_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    yield from _base_security_environment.__wrapped__(tmp_path, monkeypatch)


def test_concurrent_identical_analysis_is_persisted_once(application_service) -> None:
    content = Path("data/sample_logs/auth_sample.log").read_bytes()
    barrier = Barrier(2)

    def run(index: int):
        barrier.wait(timeout=10)
        return application_service.analyze_and_persist_source(
            analysis_name=f"concurrent-{index}",
            original_filename="auth.log",
            raw_content=content,
            connector_id="linux_auth",
            connector_options={"analysis_year": 2026},
            actor="pytest",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))

    assert sum(result.was_persisted for result in results) == 1
    assert len({result.session_uuid for result in results}) == 1
    assert len(application_service.get_analysis_history()) == 1


def test_concurrent_failed_logins_reach_lockout_threshold(security_environment) -> None:
    client, factory = security_environment
    barrier = Barrier(5)

    def fail_login(_index: int):
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/login",
            data={"username": "analyst", "password": "wrong-password"},
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        responses = list(pool.map(fail_login, range(5)))

    assert all(response.status_code == 401 for response in responses)
    assert all(response.json()["error"]["code"] == "invalid_credentials" for response in responses)
    with factory() as session:
        user = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert user is not None
        assert user.failed_login_count == 5
        assert user.locked_until is not None


def test_concurrent_refresh_rotates_once_and_detects_reuse(security_environment) -> None:
    client, factory = security_environment
    initial = login(client, "admin", "AdminPass!234")
    barrier = Barrier(2)

    def refresh_once(_index: int):
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": initial["refresh_token"]},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(refresh_once, range(2)))

    status_codes = sorted(response.status_code for response in responses)
    assert status_codes == [200, 401]
    rejected = next(response for response in responses if response.status_code == 401)
    assert rejected.json()["error"]["code"] == "refresh_reuse_detected"

    with factory() as session:
        user = session.scalar(select(UserAccountModel).where(UserAccountModel.username == "admin"))
        assert user is not None
        assert user.token_version == 2
        live_tokens = session.scalar(
            select(func.count(RefreshTokenModel.id)).where(RefreshTokenModel.revoked_at.is_(None))
        )
        # The first replacement row may remain physically unrevoked, but its tv=1 JWT is
        # invalid after reuse detection increments the account token version to 2.
        assert live_tokens == 1


def test_concurrent_refresh_and_logout_cannot_leave_replacement_session_live(
    security_environment,
) -> None:
    client, factory = security_environment
    initial = login(client, "admin", "AdminPass!234")
    barrier = Barrier(2)

    def refresh_request():
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": initial["refresh_token"]},
        )

    def logout_request():
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/logout",
            headers=auth_header(initial),
            json={"refresh_token": initial["refresh_token"]},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        refresh_future = pool.submit(refresh_request)
        logout_future = pool.submit(logout_request)
        refresh_response = refresh_future.result()
        logout_response = logout_future.result()

    assert logout_response.status_code == 204
    assert refresh_response.status_code in {200, 401}

    with factory() as session:
        user = session.scalar(select(UserAccountModel).where(UserAccountModel.username == "admin"))
        assert user is not None
        rows = list(
            session.scalars(
                select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
            ).all()
        )
        # If refresh wins, logout follows replaced_by_uuid and revokes its replacement.
        # If logout wins, refresh reuse detection creates no replacement.
        assert rows
        assert all(row.revoked_at is not None for row in rows)


def test_concurrent_administrators_cannot_remove_all_active_admins(
    security_environment,
) -> None:
    client, factory = security_environment
    admin_a = login(client, "admin", "AdminPass!234")
    created = client.post(
        "/api/v1/users",
        headers=auth_header(admin_a),
        json={
            "username": "admin2",
            "display_name": "Second Administrator",
            "password": "AdminTwoPass!234",
            "roles": ["administrator"],
        },
    )
    assert created.status_code == 201, created.text
    admin_b_uuid = created.json()["user_uuid"]
    admin_b = login(client, "admin2", "AdminTwoPass!234")
    admin_a_uuid = admin_a["user"]["user_uuid"]
    barrier = Barrier(2)

    def disable(target_uuid: str, token_payload: dict):
        barrier.wait(timeout=10)
        return client.patch(
            f"/api/v1/users/{target_uuid}",
            headers=auth_header(token_payload),
            json={"is_active": False},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(disable, admin_b_uuid, admin_a)
        future_b = pool.submit(disable, admin_a_uuid, admin_b)
        responses = [future_a.result(), future_b.result()]

    assert 200 in {response.status_code for response in responses}
    assert any(response.status_code in {401, 403, 409} for response in responses)
    with factory() as session:
        admins = session.scalars(select(UserAccountModel)).all()
        active_admins = [
            user
            for user in admins
            if user.is_active and any(role.name == "administrator" for role in user.roles)
        ]
        assert len(active_admins) >= 1


def test_concurrent_partial_incident_patches_preserve_each_other(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from database.service import ThreatLensPersistenceService

    client, _ = security_environment
    senior = login(client, "senior", "SeniorPass!234")
    state = {
        "incident_uuid": "incident-concurrent",
        "assignee": "analyst",
        "status": "open",
        "priority": "P2",
    }

    def get_details(self, incident_uuid: str):
        return {
            "incident": dict(state),
            "alerts": [],
            "events": [],
            "notes": [],
            "evidence": [],
            "audit": [],
            "correlation_entities": [],
            "correlation_relationships": [],
        }

    def update_details(self, **kwargs):
        state["status"] = kwargs["status"]
        state["assignee"] = kwargs["assignee"]
        state["priority"] = kwargs["priority"]

    monkeypatch.setattr(ThreatLensPersistenceService, "get_incident_details", get_details)
    monkeypatch.setattr(ThreatLensPersistenceService, "update_incident_workflow", update_details)
    barrier = Barrier(2)

    def patch(payload: dict):
        barrier.wait(timeout=10)
        return client.patch(
            "/api/v1/incidents/incident-concurrent/workflow",
            headers=auth_header(senior),
            json=payload,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        status_future = pool.submit(patch, {"status": "investigating"})
        priority_future = pool.submit(patch, {"priority": "P1"})
        responses = [status_future.result(), priority_future.result()]

    assert all(response.status_code == 200 for response in responses)
    assert state["status"] == "investigating"
    assert state["priority"] == "P1"
    assert state["assignee"] == "analyst"


def test_incident_note_authorization_is_rechecked_after_concurrent_reassignment(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    from app.application_service import ThreatLensApplicationService
    from database.service import ThreatLensPersistenceService

    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    senior = login(client, "senior", "SeniorPass!234")
    state = {
        "incident_uuid": "incident-note-race",
        "assignee": "analyst",
        "status": "open",
        "priority": "P2",
    }
    workflow_inside_lock = Event()
    notes_written: list[str] = []

    def details_payload():
        return {
            "incident": dict(state),
            "alerts": [],
            "events": [],
            "notes": [],
            "evidence": [],
            "audit": [],
            "correlation_entities": [],
            "correlation_relationships": [],
        }

    monkeypatch.setattr(
        ThreatLensPersistenceService,
        "get_incident_details",
        lambda self, incident_uuid: details_payload(),
    )

    def update_details(self, **kwargs):
        state["status"] = kwargs["status"]
        state["assignee"] = kwargs["assignee"]
        state["priority"] = kwargs["priority"]
        workflow_inside_lock.set()
        time.sleep(0.1)

    monkeypatch.setattr(ThreatLensPersistenceService, "update_incident_workflow", update_details)
    monkeypatch.setattr(
        ThreatLensApplicationService,
        "get_incident_details",
        lambda self, incident_uuid: details_payload(),
    )
    monkeypatch.setattr(
        ThreatLensApplicationService,
        "add_incident_note",
        lambda self, **kwargs: notes_written.append(kwargs["note"]) or "note-1",
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        workflow_future = pool.submit(
            client.patch,
            "/api/v1/incidents/incident-note-race/workflow",
            headers=auth_header(senior),
            json={"assignee": "senior"},
        )
        assert workflow_inside_lock.wait(timeout=10)
        note_future = pool.submit(
            client.post,
            "/api/v1/incidents/incident-note-race/notes",
            headers=auth_header(analyst),
            json={"note": "stale analyst note"},
        )
        workflow_response = workflow_future.result()
        note_response = note_future.result()

    assert workflow_response.status_code == 200
    assert note_response.status_code == 403
    assert note_response.json()["error"]["code"] == "incident_object_access_denied"
    assert notes_written == []


def test_concurrent_attack_catalog_synchronization_is_idempotent(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'attack-concurrent.db').as_posix()}")
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    Base.metadata.create_all(engine)

    @contextmanager
    def session_context():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    source = AttackCatalogSource(
        domain="enterprise-test",
        display_name="Enterprise ATT&CK Test",
        version="test",
        collection_id="x-mitre-collection--test",
        source_url="https://raw.githubusercontent.com/example/test.json",
        modified="2026-01-01T00:00:00.000Z",
        expected_tactics=2,
        expected_techniques=2,
        expected_subtechniques=2,
    )
    mapping = SimpleNamespace(
        technique_id="T1000.001",
        tactic="Initial Access",
        role="primary",
        confidence=0.9,
        justification="Synthetic concurrent synchronization mapping.",
    )
    rule = SimpleNamespace(
        rule_id="22222222-2222-4222-8222-222222222222",
        detection_name="concurrent_synthetic_rule",
        version=1,
        status=SimpleNamespace(value="stable"),
        logsource=SimpleNamespace(dataset="synthetic"),
        attack=[mapping],
    )
    service = AttackCatalogService(session_context_factory=session_context)
    barrier = Barrier(2)

    def synchronize(_index: int):
        barrier.wait(timeout=10)
        return service.synchronize(
            source=source,
            allow_network=False,
            bundle_path=Path("tests/fixtures/attack/enterprise-mini.json"),
            rules=[rule],
            actor="pytest",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(synchronize, range(2)))

    assert sorted(result.reused_catalog for result in results) == [False, True]
    with factory() as session:
        assert session.scalar(select(func.count(AttackCatalogVersionModel.id))) == 1
    engine.dispose()


def test_database_url_resolution_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "THREATLENS_DATABASE_URL=sqlite:///from-dotenv.db\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("THREATLENS_DATABASE_URL", raising=False)
    assert resolve_database_url(env_path) == "sqlite:///from-dotenv.db"

    monkeypatch.setenv("THREATLENS_DATABASE_URL", "sqlite:///from-process.db")
    assert resolve_database_url(env_path) == "sqlite:///from-process.db"

    monkeypatch.delenv("THREATLENS_DATABASE_URL", raising=False)
    assert resolve_database_url(tmp_path / "missing.env") == DEFAULT_DATABASE_URL


def test_official_attack_sources_pin_exact_sha256() -> None:
    assert {source.domain: source.expected_sha256 for source in ALL_ATTACK_SOURCES} == {
        "enterprise-attack": "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
        "mobile-attack": "423cbceb604770c8997845151fe7cc4813de01033b8cc50c84dd3bd0d96d8322",
        "ics-attack": "a91f659d6d03095e84089630b098edb2ed9d5cd5b1ea41369b27846cd32f2a43",
    }


def test_attack_bundle_rejects_content_hash_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(
        '{"type":"bundle","objects":[{"type":"x-mitre-collection",'
        '"id":"x-mitre-collection--expected","x_mitre_version":"19.1",'
        '"modified":"2026-05-12T14:00:00.188Z"}]}',
        encoding="utf-8",
    )
    source = AttackCatalogSource(
        domain="identity-test",
        display_name="Identity Test",
        version="19.1",
        collection_id="x-mitre-collection--expected",
        source_url=(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
            "identity-test/identity-test-19.1.json"
        ),
        modified="2026-05-12T14:00:00.188Z",
        expected_sha256="0" * 64,
    )
    assert hashlib.sha256(path.read_bytes()).hexdigest() != source.expected_sha256
    with pytest.raises(AttackCatalogDownloadError, match="SHA-256"):
        validate_attack_bundle_file(path, source)


def test_release_constraints_pin_direct_and_build_dependencies() -> None:
    text = Path("constraints-windows-py311.txt").read_text(encoding="utf-8")
    required = {
        "pip==26.2.1",
        "setuptools==84.0.0",
        "wheel==0.48.0",
        "streamlit==1.66.1",
        "Pillow==13.0.0",
        "fastapi==0.141.1",
        "starlette==1.7.0",
        "sqlalchemy==2.0.54",
        "alembic==1.20.0",
        "pytest==9.1.1",
        "ruff==0.16.8",
    }
    normalized_lines = {line.casefold() for line in text.splitlines()}
    assert {item.casefold() for item in required}.issubset(normalized_lines)

    setup = Path("scripts/setup.ps1").read_text(encoding="utf-8")
    assert "pip==26.2.1" in setup
    assert "setuptools==84.0.0" in setup
    assert "wheel==0.48.0" in setup
    assert setup.count("-c constraints-windows-py311.txt") == 3
    assert "--no-build-isolation" in setup

    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'requires = ["setuptools==84.0.0", "wheel==0.48.0"]' in pyproject


def test_current_release_docs_and_runtime_copy_are_not_stale() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    report = Path("core/report_generator.py").read_text(encoding="utf-8")
    connectors = Path("core/connectors/defaults.py").read_text(encoding="utf-8")

    assert "\n# ThreatLens AI\n" in readme[:200]
    assert f"| Current source lineage | `{THREATLENS_VERSION}` |" in readme
    assert "v1.0.0" in readme and "immutable accepted release snapshot" in readme
    assert changelog.startswith(f"# Changelog\n\n## v{THREATLENS_VERSION}")
    assert "evidence-supported prototype mappings" not in report
    assert "v0.6 governed multi-source profile" not in connectors
