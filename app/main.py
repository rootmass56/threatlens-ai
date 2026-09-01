import streamlit as st

from app.api_client import ApiClientError
from app.auth_ui import (
    build_authenticated_client,
    clear_authentication,
    render_authenticated_identity,
    render_login,
)
from app.navigation import render_navigation
from app.pages.analysis_history import render_analysis_history
from app.pages.attack_coverage import render_attack_coverage
from app.pages.attack_graph import render_attack_graph
from app.pages.audit_trail import render_audit_trail
from app.pages.case_details import render_case_details
from app.pages.connector_health import render_connector_health
from app.pages.current_analysis import render_current_analysis
from app.pages.detection_quality import render_detection_quality
from app.pages.incident_queue import render_incident_queue
from app.pages.overview import render_overview
from app.pages.rag_admin import render_rag_admin
from app.pages.reports import render_reports
from app.pages.rule_catalog import render_rule_catalog
from app.pages.security_administration import render_security_administration
from app.pages.upload import render_upload
from app.state import initialize_application_state

st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡️",
    layout="wide",
)


def render_header() -> None:
    st.title("🛡️ ThreatLens AI")
    st.subheader("Multi-Source Security Analytics and Incident Investigation Platform")
    st.caption(
        "FastAPI-secured service boundary, deterministic detection, explainable risk "
        "scoring, complete ATT&CK awareness, cross-source correlation, persistent "
        "attack graphs, auditable role-based SOC workflows and grounded AI "
        "investigation assistance."
    )


initialize_application_state()

if not st.session_state.api_access_token:
    render_login()
    st.stop()

application_service = build_authenticated_client()
try:
    current_user = application_service.current_user()
except ApiClientError as error:
    clear_authentication()
    st.error(f"Your session is no longer valid: {error}")
    st.stop()

st.session_state.authenticated_user = current_user
st.session_state.analyst_identity = current_user.get("username") or "unknown"
render_header()
render_authenticated_identity(application_service)
permissions = set(current_user.get("permissions") or [])
selected_page = render_navigation(permissions)

try:
    if selected_page == "overview":
        render_overview(application_service)
    elif selected_page == "upload":
        render_upload(application_service)
    elif selected_page == "current_analysis":
        render_current_analysis()
    elif selected_page == "analysis_history":
        render_analysis_history(application_service)
    elif selected_page == "incident_queue":
        render_incident_queue(application_service)
    elif selected_page == "case_details":
        render_case_details(application_service)
    elif selected_page == "audit_trail":
        render_audit_trail(application_service)
    elif selected_page == "rule_catalog":
        render_rule_catalog(application_service)
    elif selected_page == "detection_quality":
        render_detection_quality(application_service)
    elif selected_page == "attack_coverage":
        render_attack_coverage(application_service)
    elif selected_page == "attack_graph":
        render_attack_graph(application_service)
    elif selected_page == "connector_health":
        render_connector_health(application_service)
    elif selected_page == "reports":
        render_reports(application_service)
    elif selected_page == "rag_admin":
        render_rag_admin(application_service)
    elif selected_page == "security_administration":
        render_security_administration(application_service)
except ApiClientError as error:
    reference = f" Request ID: {error.request_id}" if error.request_id else ""
    st.error(f"API operation failed: {error}.{reference}")
