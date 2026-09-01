from __future__ import annotations

import json

import streamlit as st

from api.version import THREATLENS_VERSION
from app.api_client import ApiClientError, ThreatLensApiClient


def render_security_administration(client: ThreatLensApiClient) -> None:
    st.header("Security Administration")

    flash_message = st.session_state.pop("security_admin_flash", None)
    if flash_message:
        st.success(flash_message)
    permissions = set((st.session_state.authenticated_user or {}).get("permissions") or [])
    if "user:read" not in permissions:
        st.error("Your role cannot access security administration.")
        return

    status_tab, users_tab, create_tab, openapi_tab = st.tabs(
        ["Security Status", "Users", "Create User", "Protected OpenAPI"]
    )
    with status_tab:
        try:
            status_payload = client.security_status()
        except ApiClientError as error:
            st.error(str(error))
        else:
            metrics = st.columns(4)
            metrics[0].metric("Users", status_payload.get("user_count", 0))
            metrics[1].metric("Access token", f"{status_payload.get('access_token_minutes')} min")
            metrics[2].metric("Refresh token", f"{status_payload.get('refresh_token_hours')} h")
            metrics[3].metric(
                "Lockout",
                f"{status_payload.get('account_lockout', {}).get('attempts')} attempts",
            )
            st.json(status_payload)

    with users_tab:
        users = client.list_users()
        if users.empty:
            st.info("No user accounts are available.")
        else:
            st.dataframe(users, width="stretch", hide_index=True)
            if "user:manage" in permissions:
                selected_uuid = st.selectbox(
                    "Account to update",
                    users["user_uuid"].tolist(),
                    format_func=lambda item: users.loc[users["user_uuid"] == item, "username"].iloc[
                        0
                    ],
                )
                selected = users.loc[users["user_uuid"] == selected_uuid].iloc[0]
                roles_frame = client.list_roles()
                role_options = roles_frame["name"].tolist()
                current_roles = selected.get("roles") or []
                if not isinstance(current_roles, list):
                    current_roles = []
                with st.form("update_user_form"):
                    active = st.checkbox("Active", value=bool(selected["is_active"]))
                    roles = st.multiselect("Roles", role_options, default=current_roles)
                    unlock = st.checkbox("Clear account lockout")
                    revoke = st.checkbox("Revoke all active sessions")
                    new_password = st.text_input(
                        "New password (optional)", type="password", max_chars=256
                    )
                    update = st.form_submit_button("Update account")
                if update:
                    payload = {
                        "is_active": active,
                        "roles": roles,
                        "unlock": unlock,
                        "revoke_sessions": revoke,
                    }
                    if new_password:
                        payload["password"] = new_password
                    try:
                        client.update_user(selected_uuid, payload)
                        st.success("User account updated and audited.")
                        st.rerun()
                    except ApiClientError as error:
                        st.error(str(error))

    with create_tab:
        if "user:manage" not in permissions:
            st.info("Only administrators can create users.")
        else:
            roles_frame = client.list_roles()
            role_options = roles_frame["name"].tolist()
            with st.form("create_user_form", clear_on_submit=True):
                username = st.text_input("Username", max_chars=64)
                display_name = st.text_input("Display name", max_chars=255)
                email = st.text_input("Email (optional)", max_chars=320)
                password = st.text_input("Initial password", type="password", max_chars=256)
                roles = st.multiselect("Roles", role_options, default=["analyst"])
                create = st.form_submit_button("Create user", type="primary")
            if create:
                try:
                    client.create_user(
                        {
                            "username": username,
                            "display_name": display_name,
                            "email": email or None,
                            "password": password,
                            "roles": roles,
                        }
                    )
                    st.session_state["security_admin_flash"] = "User created and audited."
                    st.rerun()
                except ApiClientError as error:
                    st.error(str(error))

    with openapi_tab:
        if "docs:view" not in permissions:
            st.info("Your role cannot retrieve protected API documentation.")
        else:
            schema = client.protected_openapi()
            st.download_button(
                "Download protected OpenAPI JSON",
                data=json.dumps(schema, indent=2, sort_keys=True),
                file_name=f"threatlens_v{THREATLENS_VERSION}_openapi.json",
                mime="application/json",
            )
            st.caption(
                "Interactive development documentation is disabled by default. "
                "The OpenAPI contract is available only to authorized administrators."
            )
