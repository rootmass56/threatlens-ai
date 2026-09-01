from __future__ import annotations

import streamlit as st

from app.navigation_policy import (
    NAVIGATION_LABELS,
    allowed_navigation_pages,
)


def render_navigation(permissions: set[str] | None = None) -> str:
    permissions = permissions or set()
    options = allowed_navigation_pages(permissions)

    if not options:
        st.sidebar.error("No application pages are available for this account.")
        st.stop()

    requested_page = st.session_state.get("requested_page")

    if requested_page in options:
        st.session_state.primary_navigation = requested_page

    st.session_state.requested_page = None

    current_page = st.session_state.get("primary_navigation")

    if current_page not in options:
        st.session_state.primary_navigation = options[0]

    st.sidebar.title("ThreatLens AI")
    st.sidebar.caption("API-Secured SOC Analytics and Case Management")

    selected_page = st.sidebar.radio(
        "Navigation",
        options=options,
        format_func=lambda key: NAVIGATION_LABELS[key],
        key="primary_navigation",
    )

    st.sidebar.divider()

    if st.session_state.current_session_uuid:
        st.sidebar.success("Analysis loaded")
        st.sidebar.caption(st.session_state.current_session_uuid)
    else:
        st.sidebar.info("No current analysis loaded")

    if st.session_state.selected_incident_uuid:
        st.sidebar.caption("Active case")
        st.sidebar.code(
            st.session_state.selected_incident_uuid,
            language=None,
        )

    return selected_page
