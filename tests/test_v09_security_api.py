from __future__ import annotations

from collections.abc import Generator
from functools import cache
from pathlib import Path
from uuid import uuid4

import pandas as pd
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.version import THREATLENS_VERSION
from database.base import Base
from database.models import LoginAttemptModel, SecurityRoleModel, UserAccountModel


@cache
def _test_password_hash(password: str) -> str:
    from api.security import hash_password

    return hash_password(password)


@pytest.fixture()
def security_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api import security as security_module
    from api.config import SecuritySettings
    from api.dependencies import get_database_session
    from api.main import create_app
    from api.rbac import ROLE_DEFINITIONS

    test_password_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=8_192,
        parallelism=1,
        hash_len=16,
        salt_len=16,
    )
    monkeypatch.setattr(security_module, "_password_hasher", test_password_hasher)
    monkeypatch.setattr(
        security_module,
        "_FAKE_PASSWORD_HASH",
        test_password_hasher.hash("not-a-real-user-password"),
    )

    engine = create_engine(
        f"sqlite:///{(tmp_path / 'security.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with factory() as session:
        for definition in ROLE_DEFINITIONS.values():
            session.add(
                SecurityRoleModel(
                    name=definition.name,
                    description=definition.description,
                    permissions_json=sorted(definition.permissions),
                    is_system=True,
                )
            )
        session.flush()
        role_by_name = {
            role.name: role for role in session.scalars(select(SecurityRoleModel)).all()
        }
        accounts = (
            ("admin", "Administrator", "AdminPass!234", "administrator"),
            ("viewer", "Viewer", "ViewerPass!234", "viewer"),
            ("analyst", "Analyst", "AnalystPass!234", "analyst"),
            ("senior", "Senior Analyst", "SeniorPass!234", "senior_analyst"),
            (
                "commander",
                "Incident Commander",
                "CommanderPass!234",
                "incident_commander",
            ),
            ("ruleengineer", "Rule Engineer", "RuleEngineerPass!234", "rule_engineer"),
        )
        for username, display_name, password, role_name in accounts:
            user = UserAccountModel(
                user_uuid=str(uuid4()),
                username=username,
                email=None,
                display_name=display_name,
                password_hash=_test_password_hash(password),
                is_active=True,
            )
            user.roles = [role_by_name[role_name]]
            session.add(user)
        session.commit()

    settings = SecuritySettings(
        jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef",
        jwt_issuer="threatlens-test",
        jwt_audience="threatlens-test-api",
        access_token_minutes=15,
        refresh_token_hours=8,
        max_failed_logins=5,
        lockout_minutes=15,
        allowed_origins=("http://localhost:8501",),
        trusted_hosts=("testserver", "localhost", "127.0.0.1"),
        enable_development_docs=False,
        max_upload_bytes=1024 * 1024,
        max_upload_files=5,
        api_host="127.0.0.1",
        api_port=8000,
    )
    app = create_app(settings)

    def override_session() -> Generator[Session, None, None]:
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_database_session] = override_session
    with TestClient(app) as client:
        yield client, factory


def login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def auth_header(payload: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {payload['access_token']}"}


def test_login_returns_rotating_token_pair_and_security_headers(
    security_environment,
) -> None:
    client, _ = security_environment
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "AdminPass!234"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["refresh_token"]
    assert payload["user"]["roles"] == ["administrator"]
    assert "user:manage" in payload["user"]["permissions"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"


def test_failed_logins_persist_and_lock_the_account(security_environment) -> None:
    client, factory = security_environment
    for _attempt in range(1, 6):
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "analyst", "password": "wrong-password"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"
    with factory() as session:
        user = session.scalar(
            select(UserAccountModel).where(UserAccountModel.username == "analyst")
        )
        assert user is not None
        assert user.failed_login_count == 5
        assert user.locked_until is not None
        attempts = list(
            session.scalars(
                select(LoginAttemptModel).where(
                    LoginAttemptModel.username == "analyst",
                    LoginAttemptModel.successful.is_(False),
                )
            ).all()
        )
        assert len(attempts) == 5


def test_refresh_token_rotation_and_reuse_detection(security_environment) -> None:
    client, factory = security_environment
    first = login(client, "admin", "AdminPass!234")
    rotated = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first["refresh_token"]},
    )
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]

    reuse = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first["refresh_token"]},
    )
    assert reuse.status_code == 401
    assert reuse.json()["error"]["code"] == "refresh_reuse_detected"
    with factory() as session:
        user = session.scalar(select(UserAccountModel).where(UserAccountModel.username == "admin"))
        assert user is not None
        assert user.token_version == 2


def test_viewer_cannot_access_user_administration(security_environment) -> None:
    client, _ = security_environment
    viewer = login(client, "viewer", "ViewerPass!234")
    response = client.get("/api/v1/users", headers=auth_header(viewer))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


def test_administrator_can_list_users_and_download_protected_openapi(
    security_environment,
) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    users = client.get("/api/v1/users", headers=auth_header(admin))
    assert users.status_code == 200
    assert users.json()["count"] == 6

    schema = client.get("/api/v1/system/openapi", headers=auth_header(admin))
    assert schema.status_code == 200
    assert schema.json()["info"]["version"] == THREATLENS_VERSION
    assert "/api/v1/auth/login" in schema.json()["paths"]


ROLE_ACCEPTANCE_CASES = (
    ("viewer", "ViewerPass!234", "viewer", False, False, False, False),
    ("analyst", "AnalystPass!234", "analyst", True, False, False, False),
    ("senior", "SeniorPass!234", "senior_analyst", True, True, False, False),
    (
        "commander",
        "CommanderPass!234",
        "incident_commander",
        True,
        True,
        False,
        False,
    ),
    (
        "ruleengineer",
        "RuleEngineerPass!234",
        "rule_engineer",
        False,
        True,
        True,
        False,
    ),
    ("admin", "AdminPass!234", "administrator", True, True, True, True),
)


@pytest.mark.parametrize(
    (
        "username",
        "password",
        "role_name",
        "can_create_analysis",
        "can_read_audit",
        "can_sync_attack",
        "can_administer_users",
    ),
    ROLE_ACCEPTANCE_CASES,
)
def test_each_governed_role_has_behavioral_api_acceptance(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    password: str,
    role_name: str,
    can_create_analysis: bool,
    can_read_audit: bool,
    can_sync_attack: bool,
    can_administer_users: bool,
) -> None:
    from api.rbac import ROLE_DEFINITIONS
    from app.application_service import ThreatLensApplicationService

    monkeypatch.setattr(
        ThreatLensApplicationService,
        "get_audit_logs",
        lambda self, **kwargs: pd.DataFrame(),
    )
    monkeypatch.setattr(
        ThreatLensApplicationService,
        "synchronize_attack_catalog",
        lambda self, **kwargs: {"domains": [], "actor": kwargs.get("actor")},
    )

    client, _ = security_environment
    token = login(client, username, password)
    headers = auth_header(token)

    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["roles"] == [role_name]
    assert set(me.json()["permissions"]) == set(ROLE_DEFINITIONS[role_name].permissions)

    upload = client.post(
        "/api/v1/analyses/upload",
        headers=headers,
        data={"analysis_name": f"{role_name} acceptance"},
        files=[("files", ("empty.log", b"", "text/plain"))],
    )
    assert upload.status_code == (422 if can_create_analysis else 403)

    audit = client.get("/api/v1/audit", headers=headers)
    assert audit.status_code == (200 if can_read_audit else 403)

    sync = client.post(
        "/api/v1/attack/synchronize",
        headers=headers,
        json={"force_download": False},
    )
    assert sync.status_code == (200 if can_sync_attack else 403)

    users = client.get("/api/v1/users", headers=headers)
    assert users.status_code == (200 if can_administer_users else 403)

    protected_openapi = client.get("/api/v1/system/openapi", headers=headers)
    assert protected_openapi.status_code == (200 if can_administer_users else 403)


def test_development_docs_are_disabled_by_default(security_environment) -> None:
    client, _ = security_environment
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_explicit_logout_revokes_refresh_token(security_environment) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    logout_response = client.post(
        "/api/v1/auth/logout",
        headers=auth_header(admin),
        json={"refresh_token": admin["refresh_token"]},
    )
    assert logout_response.status_code == 204
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": admin["refresh_token"]},
    )
    assert refresh_response.status_code == 401


def test_weak_user_password_is_rejected(security_environment) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    response = client.post(
        "/api/v1/users",
        headers=auth_header(admin),
        json={
            "username": "weakuser",
            "display_name": "Weak User",
            "email": None,
            "password": "alllowercasepassword",
            "roles": ["analyst"],
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "user_create_failed"


def test_anonymous_sensitive_request_is_denied_with_safe_envelope(
    security_environment,
) -> None:
    client, _ = security_environment
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401
    payload = response.json()
    assert payload["error"]["code"] == "http_error"
    assert payload["error"]["request_id"] == response.headers["x-request-id"]
    assert "traceback" not in response.text.lower()


def test_upload_boundary_rejects_unsupported_and_empty_files(
    security_environment,
) -> None:
    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    headers = auth_header(analyst)

    unsupported = client.post(
        "/api/v1/analyses/upload",
        headers=headers,
        data={"analysis_name": "Unsupported upload"},
        files=[("files", ("payload.exe", b"MZ"))],
    )
    assert unsupported.status_code == 422
    assert unsupported.json()["error"]["code"] == "invalid_filename"

    empty = client.post(
        "/api/v1/analyses/upload",
        headers=headers,
        data={"analysis_name": "Empty upload"},
        files=[("files", ("empty.log", b""))],
    )
    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "empty_upload"


def test_disabled_account_cannot_authenticate(security_environment) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    users = client.get("/api/v1/users", headers=auth_header(admin)).json()["items"]
    viewer_uuid = next(item["user_uuid"] for item in users if item["username"] == "viewer")
    disabled = client.patch(
        f"/api/v1/users/{viewer_uuid}",
        headers=auth_header(admin),
        json={"is_active": False},
    )
    assert disabled.status_code == 200
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "viewer", "password": "ViewerPass!234"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


def test_last_active_administrator_cannot_be_removed(security_environment) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    admin_uuid = admin["user"]["user_uuid"]
    response = client.patch(
        f"/api/v1/users/{admin_uuid}",
        headers=auth_header(admin),
        json={"roles": ["analyst"]},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] in {
        "last_administrator_protected",
        "self_admin_removal_blocked",
    }


def test_duplicate_email_and_duplicate_roles_are_rejected(
    security_environment,
) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    headers = auth_header(admin)
    first = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "firstmail",
            "display_name": "First Mail",
            "email": "soc@example.com",
            "password": "FirstMailPass!234",
            "roles": ["analyst"],
        },
    )
    assert first.status_code == 201
    duplicate_email = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "secondmail",
            "display_name": "Second Mail",
            "email": "soc@example.com",
            "password": "SecondMailPass!234",
            "roles": ["analyst"],
        },
    )
    assert duplicate_email.status_code == 409
    duplicate_roles = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "duproles",
            "display_name": "Duplicate Roles",
            "password": "DuplicateRole!234",
            "roles": ["analyst", "analyst"],
        },
    )
    assert duplicate_roles.status_code == 422
    assert duplicate_roles.json()["error"]["code"] == "validation_failed"


def test_login_rate_limit_is_enforced(security_environment) -> None:
    client, _ = security_environment
    for _ in range(10):
        client.post(
            "/api/v1/auth/login",
            data={"username": "nobody", "password": "bad"},
        )
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nobody", "password": "bad"},
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limit_exceeded"
    assert response.headers["retry-after"]


def test_logout_rejects_refresh_token_owned_by_another_user(
    security_environment,
) -> None:
    client, _ = security_environment
    admin = login(client, "admin", "AdminPass!234")
    viewer = login(client, "viewer", "ViewerPass!234")

    rejected = client.post(
        "/api/v1/auth/logout",
        headers=auth_header(admin),
        json={"refresh_token": viewer["refresh_token"]},
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"]["code"] == "invalid_refresh_token"

    still_valid = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": viewer["refresh_token"]},
    )
    assert still_valid.status_code == 200


def test_rate_limited_responses_keep_security_headers(security_environment) -> None:
    client, _ = security_environment
    for _ in range(10):
        client.post(
            "/api/v1/auth/login",
            data={"username": "rate-header-check", "password": "bad"},
        )
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "rate-header-check", "password": "bad"},
    )
    assert response.status_code == 429
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-request-id"]


def test_streamlit_pages_use_the_api_client_boundary() -> None:
    page_root = Path(__file__).resolve().parents[1] / "app" / "pages"
    protected_pages = {
        "analysis_history.py",
        "attack_coverage.py",
        "attack_graph.py",
        "audit_trail.py",
        "case_details.py",
        "connector_health.py",
        "detection_quality.py",
        "incident_queue.py",
        "overview.py",
        "reports.py",
        "rule_catalog.py",
        "upload.py",
    }
    for filename in protected_pages:
        source = (page_root / filename).read_text(encoding="utf-8")
        assert "from app.api_client import" in source
        assert "from app.application_service import" not in source


def test_upload_content_type_spoofing_is_rejected(security_environment) -> None:
    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    response = client.post(
        "/api/v1/analyses/upload",
        headers=auth_header(analyst),
        data={"analysis_name": "Spoofed content type"},
        files=[("files", ("telemetry.log", b"not executable", "application/x-msdownload"))],
    )
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_media_type"


def test_connector_diagnostics_use_the_same_upload_security_boundary(
    security_environment,
) -> None:
    client, _ = security_environment
    viewer = login(client, "viewer", "ViewerPass!234")
    headers = auth_header(viewer)

    invalid_name = client.post(
        "/api/v1/connectors/diagnose",
        headers=headers,
        files={"file": ("diagnostic.exe", b"MZ", "application/octet-stream")},
    )
    assert invalid_name.status_code == 422
    assert invalid_name.json()["error"]["code"] == "invalid_filename"

    empty = client.post(
        "/api/v1/connectors/diagnose",
        headers=headers,
        files={"file": ("diagnostic.log", b"", "text/plain")},
    )
    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "empty_upload"


def test_every_non_public_api_operation_declares_bearer_authentication(
    security_environment,
) -> None:
    client, _ = security_environment
    schema = client.app.openapi()
    public_operations = {
        ("/api/v1/auth/login", "post"),
        ("/api/v1/auth/refresh", "post"),
        ("/api/v1/health/live", "get"),
        ("/api/v1/health/ready", "get"),
    }
    for path, path_item in schema["paths"].items():
        for method, operation in path_item.items():
            if method not in {"get", "post", "patch", "put", "delete"}:
                continue
            if (path, method) in public_operations:
                continue
            assert operation.get("security"), f"{method.upper()} {path} is unprotected"


def test_security_status_exposes_authoritative_upload_limits(security_environment) -> None:
    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    response = client.get("/api/v1/system/security", headers=auth_header(analyst))
    assert response.status_code == 200
    assert response.json()["upload_limits"] == {
        "max_file_bytes": 1024 * 1024,
        "max_files": 5,
        "max_batch_bytes": 5 * 1024 * 1024,
    }


def test_upload_source_metadata_reaches_application_service(
    security_environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from api.routes import analyses as analyses_route
    from app.application_service import ThreatLensApplicationService

    captured = {}

    def fake_analyze_sources(self, *, analysis_name, sources, actor, allow_duplicate):
        captured["analysis_name"] = analysis_name
        captured["sources"] = sources
        captured["actor"] = actor
        captured["allow_duplicate"] = allow_duplicate
        return object()

    monkeypatch.setattr(
        ThreatLensApplicationService,
        "analyze_and_persist_sources",
        fake_analyze_sources,
    )
    monkeypatch.setattr(
        analyses_route,
        "_execution_payload",
        lambda result: {"accepted": result is not None},
    )

    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")
    response = client.post(
        "/api/v1/analyses/upload",
        headers=auth_header(analyst),
        data={
            "analysis_name": "Metadata boundary",
            "allow_duplicate": "false",
            "source_metadata": json.dumps(
                [
                    {
                        "connector_id": "linux_auth",
                        "options": {"analysis_year": 2026},
                    },
                    {
                        "connector_id": "windows_sysmon",
                        "options": {},
                    },
                ]
            ),
        },
        files=[
            ("files", ("auth.log", b"Aug  7 10:00:00 host sshd[1]: test", "text/plain")),
            ("files", ("sysmon.jsonl", b"{}\n", "application/x-ndjson")),
        ],
    )
    assert response.status_code == 201, response.text
    assert response.json() == {"accepted": True}
    assert captured["analysis_name"] == "Metadata boundary"
    assert captured["actor"] == "analyst"
    assert captured["allow_duplicate"] is False
    assert [(source.connector_id, source.options) for source in captured["sources"]] == [
        ("linux_auth", {"analysis_year": 2026}),
        ("windows_sysmon", {}),
    ]
