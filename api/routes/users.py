
from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from api.dependencies import DatabaseSession, RequireUserManage, RequireUserRead
from api.rbac import ROLE_DEFINITIONS, Permission, permissions_for_roles
from api.schemas import UserCreateRequest, UserUpdateRequest
from api.security import (
    create_user,
    get_user_by_uuid,
    hash_password,
    user_record,
    validate_password_strength,
)
from api.serialization import json_safe
from database.models import AuditLogModel, RefreshTokenModel, SecurityRoleModel, UserAccountModel

router = APIRouter(prefix="/users", tags=["users"])
_USER_DIRECTORY_LOCK = Lock()


def _require_current_user_manager(
    session: DatabaseSession, principal: RequireUserManage
) -> UserAccountModel:
    actor = get_user_by_uuid(session, principal.user_uuid)
    actor_roles = {role.name for role in actor.roles} if actor is not None else set()
    if (
        actor is None
        or not actor.is_active
        or Permission.USER_MANAGE not in permissions_for_roles(actor_roles)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "stale_administrator_authority",
                "message": "Administrative authority changed before the mutation completed.",
            },
        )
    return actor


@router.get("")
def list_users(
    principal: RequireUserRead,
    session: DatabaseSession,
) -> dict[str, object]:
    del principal
    users = list(
        session.scalars(
            select(UserAccountModel)
            .options(selectinload(UserAccountModel.roles))
            .order_by(UserAccountModel.username)
        ).all()
    )
    return {"items": [user_record(user) for user in users], "count": len(users)}


@router.get("/roles")
def list_roles(principal: RequireUserRead) -> dict[str, object]:
    del principal
    return {
        "items": [
            {
                "name": role.name,
                "description": role.description,
                "permissions": sorted(role.permissions),
            }
            for role in ROLE_DEFINITIONS.values()
        ]
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_account(
    payload: UserCreateRequest,
    principal: RequireUserManage,
    session: DatabaseSession,
) -> dict[str, object]:
    # User creation and last-administrator invariants use one low-contention gate in the
    # current single-process profile. Commit before release so check-then-write decisions
    # are visible to the next administrative mutation.
    with _USER_DIRECTORY_LOCK:
        session.rollback()
        _require_current_user_manager(session, principal)
        try:
            user = create_user(
                session,
                username=payload.username,
                display_name=payload.display_name,
                email=str(payload.email) if payload.email else None,
                password=payload.password,
                role_names=payload.roles,
                actor=principal.username,
            )
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "user_create_failed", "message": str(error)},
            ) from error
        session.commit()
        return user_record(user)


@router.patch("/{user_uuid}")
def update_account(
    user_uuid: str,
    payload: UserUpdateRequest,
    principal: RequireUserManage,
    session: DatabaseSession,
) -> dict[str, object]:
    with _USER_DIRECTORY_LOCK:
        session.rollback()
        result = _update_account_locked(
            user_uuid=user_uuid,
            payload=payload,
            principal=principal,
            session=session,
        )
        session.commit()
        return result


def _update_account_locked(
    *,
    user_uuid: str,
    payload: UserUpdateRequest,
    principal: RequireUserManage,
    session: DatabaseSession,
) -> dict[str, object]:
    _require_current_user_manager(session, principal)

    user = get_user_by_uuid(session, user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "user_not_found", "message": "User account was not found."},
        )

    before = user_record(user)
    current_roles = {role.name for role in user.roles}
    requested_roles = set(payload.roles) if payload.roles is not None else current_roles
    requested_active = payload.is_active if payload.is_active is not None else user.is_active

    removing_active_administrator = (
        user.is_active
        and "administrator" in current_roles
        and (not requested_active or "administrator" not in requested_roles)
    )
    if removing_active_administrator:
        remaining_admins = (
            session.scalar(
                select(func.count(UserAccountModel.id)).where(
                    UserAccountModel.id != user.id,
                    UserAccountModel.is_active.is_(True),
                    UserAccountModel.roles.any(SecurityRoleModel.name == "administrator"),
                )
            )
            or 0
        )
        if remaining_admins == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "last_administrator_protected",
                    "message": "At least one active administrator account must remain.",
                },
            )

    if user.user_uuid == principal.user_uuid and not requested_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "self_disable_blocked",
                "message": "Administrators cannot disable their current account.",
            },
        )
    if (
        user.user_uuid == principal.user_uuid
        and "administrator" in current_roles
        and "administrator" not in requested_roles
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "self_admin_removal_blocked",
                "message": "The current administrator role cannot be removed from itself.",
            },
        )

    invalidate_sessions = False
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.email is not None:
        normalized_email = str(payload.email).lower()
        duplicate_email = session.scalars(
            select(UserAccountModel).where(
                UserAccountModel.email == normalized_email,
                UserAccountModel.id != user.id,
            )
        ).first()
        if duplicate_email is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "email_already_exists",
                    "message": "Email address is already assigned to another user.",
                },
            )
        user.email = normalized_email
    if payload.is_active is not None and user.is_active != payload.is_active:
        user.is_active = payload.is_active
        invalidate_sessions = True
    if payload.roles is not None:
        roles = list(
            session.scalars(
                select(SecurityRoleModel).where(SecurityRoleModel.name.in_(requested_roles))
            ).all()
        )
        if len(roles) != len(requested_roles):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "invalid_role", "message": "One or more roles are invalid."},
            )
        user.roles = roles
        invalidate_sessions = True
    if payload.password is not None:
        try:
            validate_password_strength(payload.password)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "weak_password", "message": str(error)},
            ) from error
        user.password_hash = hash_password(payload.password)
        invalidate_sessions = True
    if payload.unlock:
        user.failed_login_count = 0
        user.locked_until = None
    if payload.revoke_sessions:
        invalidate_sessions = True

    if invalidate_sessions:
        user.token_version += 1
        now = datetime.now(UTC)
        tokens = session.scalars(
            select(RefreshTokenModel).where(
                RefreshTokenModel.user_id == user.id,
                RefreshTokenModel.revoked_at.is_(None),
            )
        ).all()
        for token in tokens:
            token.revoked_at = now

    user.updated_at = datetime.now(UTC)
    session.add(
        AuditLogModel(
            actor=principal.username,
            action="user.updated",
            entity_type="user",
            entity_id=user.user_uuid,
            details_json=json_safe({"before": before, "after": user_record(user)}),
        )
    )
    return user_record(user)
