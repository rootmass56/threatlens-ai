from __future__ import annotations

import os

import streamlit as st

from api.version import THREATLENS_VERSION
from app.api_client import ApiClientError, ThreatLensApiClient


def _store_tokens(access_token: str, refresh_token: str, user: dict) -> None:
    st.session_state.api_access_token = access_token
    st.session_state.api_refresh_token = refresh_token
    st.session_state.authenticated_user = user


def clear_authentication() -> None:
    st.session_state.api_access_token = None
    st.session_state.api_refresh_token = None
    st.session_state.authenticated_user = {}


def render_login() -> bool:
    st.title("🛡️ ThreatLens AI")
    st.subheader("Secure SOC Analyst Sign-In")
    st.caption(
        f"ThreatLens v{THREATLENS_VERSION} uses a FastAPI security boundary, "
        "Argon2id password hashing, rotating refresh tokens, account lockout and "
        "role-based authorization."
    )
    st.caption(
        "Security posture: access/refresh tokens are kept only in the active Streamlit session "
        "and are not persisted to browser localStorage or cookies. A hard browser refresh "
        "therefore requires sign-in again by design."
    )
    api_url = os.getenv("THREATLENS_API_URL", "http://127.0.0.1:8000")
    with st.form("threatlens_login_form"):
        username = st.text_input("Username", max_chars=64)
        password = st.text_input("Password", type="password", max_chars=256)
        submitted = st.form_submit_button("Sign in", type="primary")
    if not submitted:
        st.info("Use the bootstrap administrator credentials created by scripts/setup.ps1.")
        return False
    try:
        payload = ThreatLensApiClient.login(
            username=username,
            password=password,
            base_url=api_url,
        )
    except ApiClientError as error:
        reference = f" Request ID: {error.request_id}" if error.request_id else ""
        st.error(f"Sign-in failed: {error}.{reference}")
        return False
    _store_tokens(
        payload["access_token"],
        payload["refresh_token"],
        payload["user"],
    )
    st.rerun()
    return True


def build_authenticated_client() -> ThreatLensApiClient:
    return ThreatLensApiClient(
        access_token=st.session_state.api_access_token,
        refresh_token=st.session_state.api_refresh_token,
        user=st.session_state.authenticated_user,
        token_update_callback=_store_tokens,
    )


def render_authenticated_identity(client: ThreatLensApiClient) -> None:
    user = st.session_state.authenticated_user or client.user
    st.sidebar.markdown("#### Authenticated analyst")
    st.sidebar.write(user.get("display_name") or user.get("username") or "Unknown")
    st.sidebar.caption("Roles: " + ", ".join(user.get("roles") or ["none"]))
    if st.sidebar.button("Sign out", use_container_width=True):
        client.logout()
        clear_authentication()
        st.rerun()
