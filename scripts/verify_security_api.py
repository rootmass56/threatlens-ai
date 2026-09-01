from __future__ import annotations

import json
import os
from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from api.config import SecuritySettings
from api.dependencies import get_database_session
from api.rbac import ROLE_DEFINITIONS
from api.security import create_user
from api.version import THREATLENS_VERSION
from database.base import Base
from database.models import (
    RefreshTokenModel,
    SecurityRoleModel,
    UserAccountModel,
)
from database.session import SessionLocal

_TEST_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef"


def _settings() -> SecuritySettings:
    return SecuritySettings(
        jwt_secret=_TEST_SECRET,
        jwt_issuer="threatlens-verifier",
        jwt_audience="threatlens-verifier-api",
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


def _persistent_security_status() -> dict[str, object]:
    with SessionLocal() as session:
        roles = list(
            session.scalars(select(SecurityRoleModel).order_by(SecurityRoleModel.name)).all()
        )
        active_admins = (
            session.scalar(
                select(func.count(UserAccountModel.id)).where(
                    UserAccountModel.is_active.is_(True),
                    UserAccountModel.roles.any(SecurityRoleModel.name == "administrator"),
                )
            )
            or 0
        )
    expected_names = set(ROLE_DEFINITIONS)
    actual_names = {role.name for role in roles}
    manifests_match = all(
        set(role.permissions_json) == set(ROLE_DEFINITIONS[role.name].permissions)
        for role in roles
        if role.name in ROLE_DEFINITIONS
    )
    return {
        "role_names": sorted(actual_names),
        "roles_exact": actual_names == expected_names,
        "permission_manifests_match": manifests_match and len(roles) == 6,
        "active_administrators": active_admins,
    }


def _isolated_api_checks() -> tuple[dict[str, bool], dict[str, object]]:
    os.environ.setdefault("THREATLENS_JWT_SECRET", _TEST_SECRET)
    from api.main import create_app

    with TemporaryDirectory(prefix="threatlens-v091-security-") as temp_dir:
        database_path = Path(temp_dir) / "security-verification.db"
        engine = create_engine(
            f"sqlite:///{database_path.as_posix()}",
            connect_args={"check_same_thread": False},
            poolclass=NullPool,
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
            session.commit()
            verifier_accounts = (
                ("verifier-admin", "Verifier Administrator", "VerifierAdmin!234", "administrator"),
                ("verifier-viewer", "Verifier Viewer", "VerifierViewer!234", "viewer"),
                ("verifier-analyst", "Verifier Analyst", "VerifierAnalyst!234", "analyst"),
                (
                    "verifier-senior",
                    "Verifier Senior Analyst",
                    "VerifierSenior!234",
                    "senior_analyst",
                ),
                (
                    "verifier-commander",
                    "Verifier Incident Commander",
                    "VerifierCommander!234",
                    "incident_commander",
                ),
                (
                    "verifier-rule-engineer",
                    "Verifier Rule Engineer",
                    "VerifierRuleEngineer!234",
                    "rule_engineer",
                ),
            )
            for username, display_name, password, role_name in verifier_accounts:
                create_user(
                    session,
                    username=username,
                    display_name=display_name,
                    email=None,
                    password=password,
                    role_names=[role_name],
                    actor="security-verifier",
                )
            session.commit()

        application = create_app(_settings())

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

        application.dependency_overrides[get_database_session] = override_session
        with TestClient(application) as client:
            live = client.get("/api/v1/health/live")
            ready = client.get("/api/v1/health/ready")
            anonymous = client.get("/api/v1/incidents")
            docs = client.get("/docs")
            role_credentials = {
                "administrator": ("verifier-admin", "VerifierAdmin!234"),
                "viewer": ("verifier-viewer", "VerifierViewer!234"),
                "analyst": ("verifier-analyst", "VerifierAnalyst!234"),
                "senior_analyst": ("verifier-senior", "VerifierSenior!234"),
                "incident_commander": ("verifier-commander", "VerifierCommander!234"),
                "rule_engineer": (
                    "verifier-rule-engineer",
                    "VerifierRuleEngineer!234",
                ),
            }
            role_logins = {
                role_name: client.post(
                    "/api/v1/auth/login",
                    data={"username": username, "password": password},
                )
                for role_name, (username, password) in role_credentials.items()
            }
            role_payloads = {
                role_name: response.json()
                for role_name, response in role_logins.items()
                if response.status_code == 200
            }
            role_manifests_exact = all(
                role_name in role_payloads
                and role_payloads[role_name]["user"]["roles"] == [role_name]
                and set(role_payloads[role_name]["user"]["permissions"])
                == set(ROLE_DEFINITIONS[role_name].permissions)
                for role_name in ROLE_DEFINITIONS
            )
            admin_login = role_logins["administrator"]
            viewer_login = role_logins["viewer"]
            admin_payload = role_payloads["administrator"]
            viewer_payload = role_payloads["viewer"]
            admin_headers = {"Authorization": f"Bearer {admin_payload['access_token']}"}
            viewer_headers = {"Authorization": f"Bearer {viewer_payload['access_token']}"}
            protected_openapi = client.get(
                "/api/v1/system/openapi",
                headers=admin_headers,
            )
            viewer_denied = client.get("/api/v1/users", headers=viewer_headers)
            viewer_report = client.get(
                "/api/v1/reports/analyses/missing/incident.pdf",
                headers=viewer_headers,
            )
            cross_user_logout = client.post(
                "/api/v1/auth/logout",
                headers=admin_headers,
                json={"refresh_token": viewer_payload["refresh_token"]},
            )
            viewer_refresh_after_rejected_logout = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": viewer_payload["refresh_token"]},
            )
            validation = client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={"username": "x"},
            )
            rotated = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": admin_payload["refresh_token"]},
            )
            reuse = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": admin_payload["refresh_token"]},
            )
            cors = client.options(
                "/api/v1/auth/login",
                headers={
                    "Origin": "http://localhost:8501",
                    "Access-Control-Request-Method": "POST",
                },
            )

        with factory() as session:
            admin = session.scalar(
                select(UserAccountModel).where(UserAccountModel.username == "verifier-admin")
            )
            refresh_records = list(session.scalars(select(RefreshTokenModel)).all())
            hash_only = all(
                len(record.token_hash) == 64
                and admin_payload["refresh_token"] not in record.token_hash
                for record in refresh_records
            )
            argon2id = bool(admin and admin.password_hash.startswith("$argon2id$"))

        openapi_schema = application.openapi()
        public_operations = {
            ("/api/v1/auth/login", "post"),
            ("/api/v1/auth/refresh", "post"),
            ("/api/v1/health/live", "get"),
            ("/api/v1/health/ready", "get"),
        }
        unprotected_operations: list[str] = []
        for path, path_item in openapi_schema["paths"].items():
            for method, operation in path_item.items():
                if method not in {"get", "post", "patch", "put", "delete"}:
                    continue
                if (path, method) in public_operations:
                    continue
                if not operation.get("security"):
                    unprotected_operations.append(f"{method.upper()} {path}")
        required_routes = {
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/users",
            "/api/v1/analyses/upload",
            "/api/v1/incidents/{incident_uuid}/workflow",
            "/api/v1/attack/catalogues",
            "/api/v1/graphs/{session_uuid}",
            "/api/v1/reports/analyses/{session_uuid}/incident.pdf",
            "/api/v1/system/openapi",
        }
        checks = {
            "liveness": live.status_code == 200 and live.json()["status"] == "ok",
            "readiness": ready.status_code == 200 and ready.json()["status"] == "ready",
            "anonymous_denied": anonymous.status_code == 401,
            "development_docs_disabled": docs.status_code == 404,
            "admin_authentication": admin_login.status_code == 200,
            "viewer_authentication": viewer_login.status_code == 200,
            "all_six_roles_authenticate": all(
                response.status_code == 200 for response in role_logins.values()
            ),
            "all_six_role_manifests_exact": role_manifests_exact,
            "argon2id_password_hash": argon2id,
            "access_and_refresh_tokens": bool(
                admin_payload.get("access_token") and admin_payload.get("refresh_token")
            ),
            "refresh_tokens_hashed_at_rest": hash_only,
            "refresh_rotation": rotated.status_code == 200
            and rotated.json()["refresh_token"] != admin_payload["refresh_token"],
            "refresh_reuse_detection": reuse.status_code == 401
            and reuse.json()["error"]["code"] == "refresh_reuse_detected",
            "viewer_user_admin_denied": viewer_denied.status_code == 403,
            "viewer_report_permission": viewer_report.status_code == 404,
            "cross_user_logout_denied": cross_user_logout.status_code == 401
            and cross_user_logout.json()["error"]["code"] == "invalid_refresh_token",
            "rejected_logout_preserves_owner_session": (
                viewer_refresh_after_rejected_logout.status_code == 200
            ),
            "protected_openapi": protected_openapi.status_code == 200
            and protected_openapi.json()["info"]["version"] == THREATLENS_VERSION,
            "safe_validation_envelope": validation.status_code == 422
            and validation.json()["error"]["code"] == "validation_failed",
            "security_headers": (
                admin_login.headers.get("x-content-type-options") == "nosniff"
                and admin_login.headers.get("x-frame-options") == "DENY"
                and bool(admin_login.headers.get("x-request-id"))
            ),
            "cors_allowlist": cors.status_code == 200
            and cors.headers.get("access-control-allow-origin") == "http://localhost:8501",
            "required_routes": required_routes.issubset(set(openapi_schema["paths"])),
            "all_non_public_routes_protected": not unprotected_operations,
        }
        metrics = {
            "route_count": len(openapi_schema["paths"]),
            "required_route_count": len(required_routes),
            "refresh_token_records": len(refresh_records),
            "role_count": len(ROLE_DEFINITIONS),
            "behavioral_role_count": len(role_payloads),
            "openapi_path_count": len(openapi_schema["paths"]),
            "unprotected_operations": unprotected_operations,
        }
        application.dependency_overrides.clear()
        engine.dispose()
        return checks, metrics


def build_report() -> dict[str, object]:
    persistent = _persistent_security_status()
    checks, metrics = _isolated_api_checks()
    checks.update(
        {
            "persistent_roles_exact": bool(persistent["roles_exact"]),
            "persistent_permission_manifests": bool(persistent["permission_manifests_match"]),
            "active_administrator_present": int(persistent["active_administrators"]) >= 1,
        }
    )
    return {
        "security_version": THREATLENS_VERSION,
        "checks": checks,
        "persistent_security": persistent,
        "metrics": metrics,
        "passed": all(checks.values()),
    }


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
