import hashlib

import streamlit as st

from app.api_client import ThreatLensApiClient


def render_reports(application_service: ThreatLensApiClient) -> None:
    st.header("Incident Reports")
    session_uuid = st.session_state.current_session_uuid
    if not session_uuid:
        st.warning("Load or run a persisted analysis before generating a report.")
        return

    if st.button("Generate PDF Incident Report", type="primary"):
        report_bytes, report_filename, server_sha256 = application_service.get_incident_report_pdf(
            session_uuid
        )
        local_sha256 = hashlib.sha256(report_bytes).hexdigest()
        if server_sha256 and server_sha256 != local_sha256:
            raise RuntimeError("Report integrity verification failed.")
        st.session_state.report_bytes = report_bytes
        st.session_state.report_filename = report_filename
        st.session_state.report_sha256 = local_sha256
        st.success(f"Report generated securely through FastAPI: {report_filename}")

    if st.session_state.report_bytes is not None:
        st.download_button(
            "Download PDF Report",
            data=st.session_state.report_bytes,
            file_name=st.session_state.report_filename,
            mime="application/pdf",
        )
        if st.session_state.get("report_sha256"):
            st.caption(f"SHA-256: `{st.session_state.report_sha256}`")
