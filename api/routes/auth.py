
from __future__ import annotations

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from api.dependencies import CurrentPrincipal, DatabaseSession, Settings, request_context
from api.schemas import LogoutRequest, RefreshRequest, TokenPairResponse
from api.security import (
    AccountDisabledError,
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenReuseError,
    authenticate_user,
    normalize_username,
    revoke_refresh_token,
    rotate_refresh_token,
    user_record,
)
from core.concurrency import StripedLockRegistry

router = APIRouter(prefix="/auth", tags=["authentication"])
_AUTHENTICATION_LOCKS = StripedLockRegistry()
_REFRESH_ROTATION_LOCKS = StripedLockRegistry()


def _token_response(user, tokens) -> TokenPairResponse:
    return TokenPairResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.access_expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
        user=user_record(user),
    )


@router.post("/login", response_model=TokenPairResponse)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: DatabaseSession,
    settings: Settings,
) -> TokenPairResponse:
    context = request_context(request)
    username_key = normalize_username(form.username) or "unknown"
    # FastAPI runs this synchronous route in a worker thread. Serialize stateful login
    # attempts per username and commit before releasing the lock so failed-attempt and
    # timed-lockout counters cannot lose updates under concurrent requests.
    with _AUTHENTICATION_LOCKS.lock_for(username_key):
        try:
            user, tokens = authenticate_user(
                session,
                username=form.username,
                password=form.password,
                settings=settings,
                source_ip=context["source_ip"],
                request_id=context["request_id"],
                client_fingerprint=context["client_fingerprint"],
            )
        except (AccountLockedError, AccountDisabledError, InvalidCredentialsError) as error:
            # Preserve precise reasons in server-side login/audit records while returning one
            # generic envelope to unauthenticated clients to reduce account-state enumeration.
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": "invalid_credentials",
                    "message": "Invalid username or password.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            ) from error
        session.commit()
        return _token_response(user, tokens)


@router.post("/refresh", response_model=TokenPairResponse)
def refresh(
    payload: RefreshRequest,
    request: Request,
    session: DatabaseSession,
    settings: Settings,
) -> TokenPairResponse:
    context = request_context(request)
    refresh_key = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    # Hold the token-specific gate through commit. Concurrent refreshes of the same token
    # can no longer both observe an unrevoked record and mint two live replacement chains.
    with _REFRESH_ROTATION_LOCKS.lock_for(refresh_key):
        try:
            user, tokens = rotate_refresh_token(
                session,
                refresh_token=payload.refresh_token,
                settings=settings,
                client_fingerprint=context["client_fingerprint"],
            )
        except TokenReuseError as error:
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "refresh_reuse_detected", "message": str(error)},
            ) from error
        except InvalidTokenError as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "invalid_refresh_token", "message": str(error)},
            ) from error
        session.commit()
        return _token_response(user, tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: LogoutRequest,
    principal: CurrentPrincipal,
    session: DatabaseSession,
    settings: Settings,
) -> None:
    refresh_key = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    with _REFRESH_ROTATION_LOCKS.lock_for(refresh_key):
        # The access-token dependency has already opened a read transaction. Refresh the
        # view before revoking this token chain, then commit before releasing the gate.
        session.rollback()
        try:
            revoke_refresh_token(
                session,
                refresh_token=payload.refresh_token,
                settings=settings,
                actor=principal.username,
                expected_user_uuid=principal.user_uuid,
            )
        except InvalidTokenError as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "invalid_refresh_token", "message": str(error)},
            ) from error
        session.commit()


@router.get("/me")
def me(principal: CurrentPrincipal) -> dict[str, object]:
    return principal.as_dict()
