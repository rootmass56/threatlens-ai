import plotly.express as px
import streamlit as st

from app.api_client import ThreatLensApiClient


def render_overview(application_service: ThreatLensApiClient) -> None:
    st.header("SOC Operations Overview")
    metrics = application_service.get_persistent_metrics()

    row_one = st.columns(4)
    row_one[0].metric("Analysis Sessions", metrics["total_analyses"])
    row_one[1].metric("Events Processed", metrics["total_events"])
    row_one[2].metric("Alerts Generated", metrics["total_alerts"])
    row_one[3].metric("Incidents Created", metrics["total_incidents"])

    row_two = st.columns(6)
    row_two[0].metric("Open", metrics["open_incidents"])
    row_two[1].metric("Critical", metrics["critical_incidents"])
    row_two[2].metric("Investigating", metrics["investigating_incidents"])
    row_two[3].metric("Resolved", metrics["resolved_incidents"])
    row_two[4].metric("False Positive", metrics["false_positive_incidents"])
    row_two[5].metric("Quarantined", metrics.get("total_quarantined", 0))

    rule_validation = application_service.get_rule_validation()
    if rule_validation["valid"]:
        st.success(
            f"External rule catalog healthy: {rule_validation['enabled']} enabled rules, "
            "zero validation issues."
        )
    else:
        st.error(f"Rule catalog blocked: {rule_validation['issues']} validation issues.")

    incidents_df = application_service.get_incident_queue(limit=1000)
    history_df = application_service.get_analysis_history(limit=100)
    left, right = st.columns(2)

    with left:
        st.subheader("Incident Severity")
        if incidents_df.empty:
            st.info("No persistent incidents are available.")
        else:
            data = (
                incidents_df["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            st.plotly_chart(
                px.bar(data, x="Severity", y="Count", title="Incidents by Severity"),
                width="stretch",
            )

    with right:
        st.subheader("Case Workflow")
        if incidents_df.empty:
            st.info("No workflow data is available.")
        else:
            data = (
                incidents_df["status"]
                .value_counts()
                .rename_axis("Status")
                .reset_index(name="Count")
            )
            st.plotly_chart(
                px.pie(data, names="Status", values="Count", title="Incident Status"),
                width="stretch",
            )

    st.subheader("Recent Analyses")
    if history_df.empty:
        st.info("Analyze a supported log source to create persistent history.")
    else:
        columns = [
            "session_uuid",
            "name",
            "connector_id",
            "schema_version",
            "rule_catalog_version",
            "filename",
            "events",
            "alerts",
            "incidents",
            "quarantined",
            "parse_success_rate",
            "status",
            "completed_at",
        ]
        st.dataframe(history_df[columns].head(10), width="stretch", hide_index=True)
