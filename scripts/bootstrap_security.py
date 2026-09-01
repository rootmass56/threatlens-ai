from __future__ import annotations

import os
import secrets
import string

from dotenv import load_dotenv
from sqlalchemy import select

from api.config import is_unsafe_jwt_secret
from api.rbac import ROLE_DEFINITIONS
from api.security import (
    create_user,
    get_user_by_username,
    hash_password,
    validate_password_strength,
)
from api.version import THREATLENS_VERSION
from database.models import SecurityRoleModel
from database.session import ROOT_DIR, session_scope

ENV_PATH = ROOT_DIR / ".env"
CREDENTIALS_PATH = ROOT_DIR / "data" / "bootstrap_admin_credentials.txt"


def _load_env_lines() -> list[str]:
    if not ENV_PATH.exists():
        return []
    return ENV_PATH.read_text(encoding="utf-8").splitlines()


def _set_env_value(name: str, value: str) -> None:
    lines = _load_env_lines()
    output: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{name}="):
            output.append(f"{name}={value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{name}={value}")
    ENV_PATH.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    os.environ[name] = value


def _generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        try:
            validate_password_strength(password)
            return password
        except ValueError:
            continue


def bootstrap() -> None:
    load_dotenv(ENV_PATH, override=False)
    secret = os.getenv("THREATLENS_JWT_SECRET", "").strip()
    if is_unsafe_jwt_secret(secret):
        secret = secrets.token_hex(48)
        _set_env_value("THREATLENS_JWT_SECRET", secret)
        print("Generated THREATLENS_JWT_SECRET in .env.")
    defaults = {
        "THREATLENS_JWT_ISSUER": "threatlens-ai",
        "THREATLENS_JWT_AUDIENCE": "threatlens-api",
        "THREATLENS_API_URL": "http://127.0.0.1:8000",
        "THREATLENS_ALLOWED_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173",
        "THREATLENS_TRUSTED_HOSTS": "localhost,127.0.0.1,testserver",
    }
    for name, value in defaults.items():
        if not os.getenv(name):
            _set_env_value(name, value)

    username = os.getenv("THREATLENS_BOOTSTRAP_ADMIN_USERNAME", "admin").strip().lower()
    supplied_password = os.getenv("THREATLENS_BOOTSTRAP_ADMIN_PASSWORD", "")
    generated_password = supplied_password or _generate_password()
    reset = os.getenv("THREATLENS_RESET_BOOTSTRAP_ADMIN", "0") == "1"

    with session_scope() as session:
        roles: dict[str, SecurityRoleModel] = {}
        for definition in ROLE_DEFINITIONS.values():
            role = session.scalars(
                select(SecurityRoleModel).where(SecurityRoleModel.name == definition.name)
            ).first()
            if role is None:
                role = SecurityRoleModel(
                    name=definition.name,
                    description=definition.description,
                    permissions_json=sorted(definition.permissions),
                    is_system=True,
                )
                session.add(role)
                session.flush()
            else:
                role.description = definition.description
                role.permissions_json = sorted(definition.permissions)
            roles[definition.name] = role

        user = get_user_by_username(session, username)
        created = False
        if user is None:
            user = create_user(
                session,
                username=username,
                display_name="ThreatLens Administrator",
                email=None,
                password=generated_password,
                role_names=["administrator"],
                actor="bootstrap",
            )
            created = True
        elif reset:
            user.password_hash = hash_password(generated_password)
            user.is_active = True
            user.failed_login_count = 0
            user.locked_until = None
            user.token_version += 1
            user.roles = [roles["administrator"]]
            created = True

    if created:
        if supplied_password:
            print(
                "Bootstrap administrator created/reset using "
                "THREATLENS_BOOTSTRAP_ADMIN_PASSWORD; no credential file was written."
            )
        else:
            CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
            CREDENTIALS_PATH.write_text(
                f"ThreatLens AI v{THREATLENS_VERSION} bootstrap administrator\n"
                f"Username: {username}\n"
                f"Password: {generated_password}\n"
                "Change this password after first login. Delete this file after "
                "recording it securely.\n",
                encoding="utf-8",
            )
            print(f"Bootstrap administrator credentials: {CREDENTIALS_PATH}")
    else:
        print(f"Administrator account '{username}' already exists; password was not changed.")
    print("Security roles and authentication bootstrap completed.")


if __name__ == "__main__":
    bootstrap()
