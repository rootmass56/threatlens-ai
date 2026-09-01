import json

import streamlit as st

from app.api_client import ThreatLensApiClient


def render_audit_trail(application_service: ThreatLensApiClient) -> None:
    st.header("Audit Trail")
    filters = st.columns(2)
    entity_type = filters[0].text_input("Entity type filter")
    entity_id = filters[1].text_input("Entity ID filter")
    audit_df = application_service.get_audit_logs(
        entity_type=entity_type.strip() or None,
        entity_id=entity_id.strip() or None,
        limit=2000,
    )
    if audit_df.empty:
        st.info("No matching audit records are available.")
        return
    if "details" in audit_df.columns:
        audit_df["details"] = audit_df["details"].apply(
            lambda value: json.dumps(value, sort_keys=True)
        )
    st.metric("Audit Records", len(audit_df))
    st.dataframe(audit_df, width="stretch", hide_index=True)
    st.download_button(
        "Download Audit CSV",
        data=audit_df.to_csv(index=False).encode("utf-8"),
        file_name="threatlens_audit_trail.csv",
        mime="text/csv",
    )
