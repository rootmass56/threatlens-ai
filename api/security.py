
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.config import SecuritySettings
from api.rbac import permissions_for_roles
from database.models import (
    AuditLogModel,
    LoginAttemptModel,
    RefreshTokenModel,
    SecurityRoleModel,
    UserAccountModel,
    utc_now,
)

_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
_FAKE_PASSWORD_HASH = _password_hasher.hash("not-a-real-user-password")


class AuthenticationError(Exception):
    """Base authentication failure."""


class InvalidCredentialsError(AuthenticationError):
    pass


class AccountLockedError(AuthenticationError):
    def __init__(self, locked_until: datetime) -> None:
        super().__init__("Account is temporarily locked.")
        self.locked_until = locked_until


class AccountDisabledError(AuthenticationError):
    pass


class InvalidTokenError(AuthenticationError):
    pass


class TokenReuseError(AuthenticationError):
    pass


@dataclass(frozen=True)
class Principal:
    user_uuid: str
    username: str
    display_name: str
    roles: frozenset[str]
    permissions: frozenset[str]
    token_jti: str

    def as_dict(self) -> dict[str, object]:
        return {
            "user_uuid": self.user_uuid,
            "username": self.username,
            "display_name": self.display_name,
            "roles": sorted(self.roles),
            "permissions": sorted(self.permissions),
        }


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def normalize_username(value: str) -> str:
    return value.strip().lower()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    checks = (
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )
    if sum(checks) < 3:
        raise ValueError(
            "Password must include at least three of lowercase, uppercase, digit, and symbol."
        )


def _user_statement(username: str):
    return (
        select(UserAccountModel)
        .where(UserAccountModel.username == normalize_username(username))
        .options(selectinload(UserAccountModel.roles))
    )


def get_user_by_username(session: Session, username: str) -> UserAccountModel | None:
    return session.scalars(_user_statement(username)).first()


def get_user_by_uuid(session: Session, user_uuid: str) -> UserAccountModel | None:
    statement = (
        select(UserAccountModel)
        .where(UserAccountModel.user_uuid == user_uuid)
        .options(selectinload(UserAccountModel.roles))
    )
    return session.scalars(statement).first()


def _write_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, object],
) -> None:
    session.add(
        AuditLogModel(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details_json=details,
        )
    )


def _record_attempt(
    session: Session,
    *,
    username: str,
    source_ip: str | None,
    successful: bool,
    reason: str,
    request_id: str | None,
) -> None:
    session.add(
        LoginAttemptModel(
            username=normalize_username(username)[:64],
            source_ip=(source_ip or "")[:64] or None,
            successful=successful,
            reason=reason[:128],
            request_id=(request_id or "")[:64] or None,
        )
    )


def _refresh_hash(token: str, settings: SecuritySettings) -> str:
    return hmac.new(
        settings.jwt_secret.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _encode_token(
    *,
    settings: SecuritySettings,
    user: UserAccountModel,
    token_type: str,
    lifetime: timedelta,
    token_uuid: str,
) -> str:
    now = datetime.now(UTC)
    role_names = sorted(role.name for role in user.roles)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": user.user_uuid,
        "username": user.username,
        "roles": role_names,
        "type": token_type,
        "jti": token_uuid,
        "tv": user.token_version,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def issue_token_pair(
    session: Session,
    *,
    user: UserAccountModel,
    settings: SecuritySettings,
    client_fingerprint: str | None = None,
) -> TokenPair:
    access_uuid = str(uuid4())
    refresh_uuid = str(uuid4())
    access_lifetime = timedelta(minutes=settings.access_token_minutes)
    refresh_lifetime = timedelta(hours=settings.refresh_token_hours)
    access_token = _encode_token(
        settings=settings,
        user=user,
        token_type="access",
        lifetime=access_lifetime,
        token_uuid=access_uuid,
    )
    refresh_token = _encode_token(
        settings=settings,
        user=user,
        token_type="refresh",
        lifetime=refresh_lifetime,
        token_uuid=refresh_uuid,
    )
    session.add(
        RefreshTokenModel(
            token_uuid=refresh_uuid,
            user_id=user.id,
            token_hash=_refresh_hash(refresh_token, settings),
            client_fingerprint=(client_fingerprint or "")[:128] or None,
            expires_at=datetime.now(UTC) + refresh_lifetime,
        )
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_in=int(access_lifetime.total_seconds()),
        refresh_expires_in=int(refresh_lifetime.total_seconds()),
    )


def authenticate_user(
    session: Session,
    *,
    username: str,
    password: str,
    settings: SecuritySettings,
    source_ip: str | None,
    request_id: str | None,
    client_fingerprint: str | None,
) -> tuple[UserAccountModel, TokenPair]:
    normalized = normalize_username(username)
    user = get_user_by_username(session, normalized)
    now = datetime.now(UTC)
    if user is None:
        verify_password(password, _FAKE_PASSWORD_HASH)
        _record_attempt(
            session,
            username=normalized,
            source_ip=source_ip,
            successful=False,
            reason="invalid_credentials",
            request_id=request_id,
        )
        _write_audit(
            session,
            actor=normalized or "unknown",
            action="auth.login_failed",
            entity_type="user",
            entity_id=normalized or "unknown",
            details={"reason": "invalid_credentials", "source_ip": source_ip},
        )
        raise InvalidCredentialsError("Invalid username or password.")
    if not user.is_active:
        # Perform the password work even for disabled accounts so unauthenticated clients
        # cannot cheaply distinguish account state from timing alone.
        verify_password(password, user.password_hash)
        _record_attempt(
            session,
            username=normalized,
            source_ip=source_ip,
            successful=False,
            reason="account_disabled",
            request_id=request_id,
        )
        _write_audit(
            session,
            actor=normalized,
            action="auth.login_blocked",
            entity_type="user",
            entity_id=user.user_uuid,
            details={"reason": "account_disabled", "source_ip": source_ip},
        )
        raise AccountDisabledError("Account is disabled.")
    if user.locked_until is not None:
        locked_until = _as_utc(user.locked_until)
        if locked_until > now:
            verify_password(password, user.password_hash)
            _record_attempt(
                session,
                username=normalized,
                source_ip=source_ip,
                successful=False,
                reason="account_locked",
                request_id=request_id,
            )
            _write_audit(
                session,
                actor=normalized,
                action="auth.login_blocked",
                entity_type="user",
                entity_id=user.user_uuid,
                details={"reason": "account_locked", "source_ip": source_ip},
            )
            raise AccountLockedError(user.locked_until)

        # A timed lockout is a bounded failure window. Once it expires, the next
        # authentication attempt starts with a fresh failure counter.
        user.failed_login_count = 0
        user.locked_until = None
        _write_audit(
            session,
            actor=normalized,
            action="auth.lockout_expired",
            entity_type="user",
            entity_id=user.user_uuid,
            details={"expired_at": locked_until.isoformat(), "source_ip": source_ip},
        )
    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            reason = "account_locked"
        else:
            reason = "invalid_credentials"
        _record_attempt(
            session,
            username=normalized,
            source_ip=source_ip,
            successful=False,
            reason=reason,
            request_id=request_id,
        )
        _write_audit(
            session,
            actor=normalized,
            action="auth.login_failed",
            entity_type="user",
            entity_id=user.user_uuid,
            details={
                "reason": reason,
                "failed_login_count": user.failed_login_count,
                "source_ip": source_ip,
            },
        )
        if user.locked_until is not None:
            raise AccountLockedError(user.locked_until)
        raise InvalidCredentialsError("Invalid username or password.")
    if _password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    _record_attempt(
        session,
        username=normalized,
        source_ip=source_ip,
        successful=True,
        reason="success",
        request_id=request_id,
    )
    tokens = issue_token_pair(
        session,
        user=user,
        settings=settings,
        client_fingerprint=client_fingerprint,
    )
    _write_audit(
        session,
        actor=user.username,
        action="auth.login_succeeded",
        entity_type="user",
        entity_id=user.user_uuid,
        details={"source_ip": source_ip, "request_id": request_id},
    )
    return user, tokens


def decode_token(
    token: str,
    *,
    settings: SecuritySettings,
    expected_type: str,
) -> dict[str, object]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "nbf", "jti", "sub", "type", "tv"]},
        )
    except jwt.PyJWTError as error:
        raise InvalidTokenError("Token is invalid or expired.") from error
    if payload.get("type") != expected_type:
        raise InvalidTokenError("Token type is invalid.")
    return payload


def principal_from_access_token(
    session: Session,
    *,
    token: str,
    settings: SecuritySettings,
) -> Principal:
    payload = decode_token(token, settings=settings, expected_type="access")
    user = get_user_by_uuid(session, str(payload["sub"]))
    if user is None or not user.is_active:
        raise InvalidTokenError("User is not active.")
    if int(payload.get("tv", -1)) != user.token_version:
        raise InvalidTokenError("Token has been revoked.")
    role_names = frozenset(role.name for role in user.roles)
    return Principal(
        user_uuid=user.user_uuid,
        username=user.username,
        display_name=user.display_name,
        roles=role_names,
        permissions=permissions_for_roles(role_names),
        token_jti=str(payload["jti"]),
    )


def rotate_refresh_token(
    session: Session,
    *,
    refresh_token: str,
    settings: SecuritySettings,
    client_fingerprint: str | None,
) -> tuple[UserAccountModel, TokenPair]:
    payload = decode_token(refresh_token, settings=settings, expected_type="refresh")
    token_uuid = str(payload["jti"])
    statement = select(RefreshTokenModel).where(RefreshTokenModel.token_uuid == token_uuid)
    record = session.scalars(statement).first()
    if record is None:
        raise InvalidTokenError("Refresh token is not recognized.")
    user = get_user_by_uuid(session, str(payload["sub"]))
    if user is None or record.user_id != user.id:
        raise InvalidTokenError("Refresh token subject does not match its server record.")
    if record.revoked_at is not None:
        user.token_version += 1
        _write_audit(
            session,
            actor=user.username,
            action="auth.refresh_reuse_detected",
            entity_type="user",
            entity_id=user.user_uuid,
            details={"token_uuid": token_uuid},
        )
        raise TokenReuseError("Revoked refresh token reuse was detected.")
    if _as_utc(record.expires_at) <= datetime.now(UTC):
        raise InvalidTokenError("Refresh token has expired.")
    if not hmac.compare_digest(record.token_hash, _refresh_hash(refresh_token, settings)):
        raise InvalidTokenError("Refresh token validation failed.")
    if not user.is_active:
        raise InvalidTokenError("User is not active.")
    if int(payload.get("tv", -1)) != user.token_version:
        raise InvalidTokenError("Refresh token has been revoked.")
    record.revoked_at = utc_now()
    record.last_used_at = utc_now()
    new_pair = issue_token_pair(
        session,
        user=user,
        settings=settings,
        client_fingerprint=client_fingerprint,
    )
    new_payload = decode_token(
        new_pair.refresh_token,
        settings=settings,
        expected_type="refresh",
    )
    record.replaced_by_uuid = str(new_payload["jti"])
    _write_audit(
        session,
        actor=user.username,
        action="auth.refresh_rotated",
        entity_type="user",
        entity_id=user.user_uuid,
        details={"old_token_uuid": token_uuid, "new_token_uuid": record.replaced_by_uuid},
    )
    return user, new_pair


def revoke_refresh_token(
    session: Session,
    *,
    refresh_token: str,
    settings: SecuritySettings,
    actor: str,
    expected_user_uuid: str,
) -> None:
    payload = decode_token(refresh_token, settings=settings, expected_type="refresh")
    token_uuid = str(payload["jti"])
    record = session.scalars(
        select(RefreshTokenModel).where(RefreshTokenModel.token_uuid == token_uuid)
    ).first()
    if str(payload["sub"]) != expected_user_uuid:
        raise InvalidTokenError("Refresh token does not belong to the authenticated user.")
    user = get_user_by_uuid(session, expected_user_uuid)
    if record is None or user is None or record.user_id != user.id:
        raise InvalidTokenError("Refresh token is not recognized for this user.")
    now = utc_now()
    revoked_chain: list[str] = []
    current = record
    visited: set[str] = set()
    while current is not None and current.token_uuid not in visited:
        visited.add(current.token_uuid)
        if current.revoked_at is None:
            current.revoked_at = now
        revoked_chain.append(current.token_uuid)
        next_uuid = current.replaced_by_uuid
        if not next_uuid:
            break
        next_record = session.scalars(
            select(RefreshTokenModel).where(RefreshTokenModel.token_uuid == next_uuid)
        ).first()
        if next_record is None or next_record.user_id != user.id:
            break
        current = next_record
    _write_audit(
        session,
        actor=actor,
        action="auth.logout",
        entity_type="refresh_token",
        entity_id=token_uuid,
        details={"revoked_chain": revoked_chain},
    )


def user_record(user: UserAccountModel) -> dict[str, object]:
    roles = sorted(role.name for role in user.roles)
    return {
        "user_uuid": user.user_uuid,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "roles": roles,
        "permissions": sorted(permissions_for_roles(frozenset(roles))),
        "failed_login_count": user.failed_login_count,
        "locked_until": user.locked_until,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def create_user(
    session: Session,
    *,
    username: str,
    display_name: str,
    email: str | None,
    password: str,
    role_names: list[str],
    actor: str,
) -> UserAccountModel:
    normalized = normalize_username(username)
    if get_user_by_username(session, normalized) is not None:
        raise ValueError("Username already exists.")
    normalized_email = email.strip().lower() if email else None
    if normalized_email is not None:
        existing_email = session.scalars(
            select(UserAccountModel).where(UserAccountModel.email == normalized_email)
        ).first()
        if existing_email is not None:
            raise ValueError("Email address already exists.")
    validate_password_strength(password)
    roles = list(
        session.scalars(
            select(SecurityRoleModel).where(SecurityRoleModel.name.in_(set(role_names)))
        ).all()
    )
    if len(roles) != len(set(role_names)):
        raise ValueError("One or more roles are invalid.")
    user = UserAccountModel(
        user_uuid=str(uuid4()),
        username=normalized,
        email=normalized_email,
        display_name=display_name.strip(),
        password_hash=hash_password(password),
        is_active=True,
    )
    user.roles.extend(roles)
    session.add(user)
    session.flush()
    _write_audit(
        session,
        actor=actor,
        action="user.created",
        entity_type="user",
        entity_id=user.user_uuid,
        details={"username": normalized, "roles": sorted(role_names)},
    )
    return user
