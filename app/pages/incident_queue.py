import streamlit as st

from app.api_client import ThreatLensApiClient


def render_incident_queue(application_service: ThreatLensApiClient) -> None:
    st.header("SOC Incident Queue")
    incidents_df = application_service.get_incident_queue(limit=1000)
    if incidents_df.empty:
        st.info("No persistent incidents are available.")
        return

    filters = st.columns(4)
    severities = sorted(incidents_df["severity"].dropna().unique().tolist())
    statuses = sorted(incidents_df["status"].dropna().unique().tolist())
    priorities = sorted(incidents_df["priority"].dropna().unique().tolist())
    selected_severities = filters[0].multiselect("Severity", severities, default=severities)
    selected_statuses = filters[1].multiselect("Status", statuses, default=statuses)
    selected_priorities = filters[2].multiselect("Priority", priorities, default=priorities)
    assignee_search = filters[3].text_input("Assignee contains")

    filtered = incidents_df[
        incidents_df["severity"].isin(selected_severities)
        & incidents_df["status"].isin(selected_statuses)
        & incidents_df["priority"].isin(selected_priorities)
    ].copy()
    if assignee_search:
        filtered = filtered[
            filtered["assignee"].fillna("").str.contains(assignee_search, case=False, regex=False)
        ]

    metrics = st.columns(4)
    metrics[0].metric("Matching", len(filtered))
    metrics[1].metric("P1", int((filtered["priority"] == "P1").sum()))
    metrics[2].metric("Critical", int((filtered["severity"] == "Critical").sum()))
    metrics[3].metric("Unassigned", int(filtered["assignee"].fillna("").eq("").sum()))
    st.dataframe(filtered, width="stretch", hide_index=True)

    if filtered.empty:
        return
    incident_options = filtered["incident_uuid"].tolist()
    selected_uuid = st.selectbox(
        "Select a case",
        options=incident_options,
        format_func=lambda uuid: (
            f"{filtered.loc[filtered['incident_uuid'] == uuid, 'title'].iloc[0]} — {uuid}"
        ),
    )
    if st.button("Open Case", type="primary"):
        st.session_state.selected_incident_uuid = selected_uuid
        st.session_state.requested_page = "case_details"
        st.rerun()
