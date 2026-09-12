from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env", override=False)

UNSAFE_JWT_SECRET_VALUES = frozenset(
    {
        "replace-with-at-least-32-random-characters",
        "change-me",
        "changeme",
        "your-secret-key",
        "example-secret",
    }
)


def is_unsafe_jwt_secret(value: str) -> bool:
    """Reject empty, short and known example JWT signing secrets."""

    secret = value.strip()
    lowered = secret.lower()
    return (
        len(secret) < 32
        or lowered in UNSAFE_JWT_SECRET_VALUES
        or lowered.startswith("replace-with-")
    )


def _as_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(name: str, default: int, minimum: int = 1) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}.")
    return parsed


def _csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.getenv(name)
    if value is None:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class SecuritySettings:
    """Runtime security configuration loaded from environment variables."""

    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str
    access_token_minutes: int
    refresh_token_hours: int
    max_failed_logins: int
    lockout_minutes: int
    allowed_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    enable_development_docs: bool
    max_upload_bytes: int
    max_upload_files: int
    api_host: str
    api_port: int
    structured_logging: bool = False
    log_level: str = "INFO"
    metrics_enabled: bool = True
    slow_request_ms: int = 1000
    https_only: bool = False
    max_request_body_bytes: int = 120 * 1024 * 1024

    @classmethod
    def from_environment(cls) -> SecuritySettings:
        secret = os.getenv("THREATLENS_JWT_SECRET", "").strip()
        if is_unsafe_jwt_secret(secret):
            raise RuntimeError(
                "THREATLENS_JWT_SECRET must be a non-placeholder secret containing at least "
                "32 characters. Run scripts/bootstrap_security.py or scripts/setup.ps1."
            )
        return cls(
            jwt_secret=secret,
            jwt_issuer=os.getenv("THREATLENS_JWT_ISSUER", "threatlens-ai").strip(),
            jwt_audience=os.getenv("THREATLENS_JWT_AUDIENCE", "threatlens-api").strip(),
            access_token_minutes=_as_int("THREATLENS_ACCESS_TOKEN_MINUTES", 15),
            refresh_token_hours=_as_int("THREATLENS_REFRESH_TOKEN_HOURS", 8),
            max_failed_logins=_as_int("THREATLENS_MAX_FAILED_LOGINS", 5),
            lockout_minutes=_as_int("THREATLENS_LOCKOUT_MINUTES", 15),
            allowed_origins=_csv(
                "THREATLENS_ALLOWED_ORIGINS",
                ("http://localhost:5173", "http://127.0.0.1:5173"),
            ),
            trusted_hosts=_csv(
                "THREATLENS_TRUSTED_HOSTS",
                ("localhost", "127.0.0.1", "testserver"),
            ),
            enable_development_docs=_as_bool("THREATLENS_ENABLE_DEVELOPMENT_DOCS", False),
            max_upload_bytes=_as_int("THREATLENS_MAX_UPLOAD_BYTES", 10 * 1024 * 1024),
            max_upload_files=_as_int("THREATLENS_MAX_UPLOAD_FILES", 10),
            api_host=os.getenv("THREATLENS_API_HOST", "127.0.0.1").strip(),
            api_port=_as_int("THREATLENS_API_PORT", 8000),
            structured_logging=_as_bool("THREATLENS_STRUCTURED_LOGGING", False),
            log_level=os.getenv("THREATLENS_LOG_LEVEL", "INFO").strip().upper() or "INFO",
            metrics_enabled=_as_bool("THREATLENS_METRICS_ENABLED", True),
            slow_request_ms=_as_int("THREATLENS_SLOW_REQUEST_MS", 1000),
            https_only=_as_bool("THREATLENS_HTTPS_ONLY", False),
            max_request_body_bytes=_as_int(
                "THREATLENS_MAX_REQUEST_BODY_BYTES",
                120 * 1024 * 1024,
            ),
        )


@lru_cache(maxsize=1)
def get_security_settings() -> SecuritySettings:
    return SecuritySettings.from_environment()
