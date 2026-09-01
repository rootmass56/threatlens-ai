import plotly.express as px
import streamlit as st


def render_current_analysis() -> None:
    st.header("Current Analysis Workspace")
    events_df = st.session_state.events_df
    alerts_df = st.session_state.alerts_df
    incidents_df = st.session_state.incidents_df
    timeline_df = st.session_state.timeline_df
    quarantined_df = st.session_state.quarantined_df
    source_manifest_df = st.session_state.source_manifest_df
    if events_df.empty:
        st.warning("No current analysis is loaded. Use Upload and Analyze or Analysis History.")
        return

    statistics = st.session_state.parser_statistics
    source_count = int(statistics.get("source_count") or 0)
    if source_count <= 0:
        source_count = len(source_manifest_df)
    if source_count <= 0 and not events_df.empty:
        source_count = 1
    quarantined_count = int(
        statistics.get("quarantined_records")
        or st.session_state.current_quarantined_count
        or len(quarantined_df)
    )
    loaded_rule_count = st.session_state.loaded_rule_count

    metrics = st.columns(7)
    metrics[0].metric("Sources", source_count)
    metrics[1].metric("Events", len(events_df))
    metrics[2].metric("Alerts", len(alerts_df))
    metrics[3].metric("Incidents", len(incidents_df))
    critical = int((alerts_df["severity"] == "Critical").sum()) if not alerts_df.empty else 0
    metrics[4].metric("Critical Alerts", critical)
    metrics[5].metric("Quarantined", quarantined_count)
    metrics[6].metric(
        "Rules Loaded",
        loaded_rule_count if loaded_rule_count is not None else "N/A",
    )
    st.caption(f"Session: {st.session_state.current_session_uuid}")
    st.caption(
        f"Analysis: {st.session_state.current_analysis_name} | "
        f"Connectors: {', '.join(st.session_state.current_connector_ids) or 'unknown'}"
    )

    tabs = st.tabs(
        [
            "Source Manifest",
            "Normalized Events",
            "Parser Quality",
            "Alerts",
            "Incidents",
            "Timeline",
            "Correlation Evidence",
        ]
    )
    with tabs[0]:
        if source_manifest_df.empty:
            st.info(
                "Source manifest metadata is unavailable for this persisted analysis. "
                "Sessions created after source-manifest persistence was introduced should "
                "normally include it."
            )
        else:
            st.dataframe(source_manifest_df, width="stretch", hide_index=True)
            st.download_button(
                "Download Source Manifest CSV",
                data=source_manifest_df.to_csv(index=False).encode("utf-8"),
                file_name="threatlens_source_manifest.csv",
                mime="text/csv",
            )
    with tabs[1]:
        st.dataframe(events_df, width="stretch", hide_index=True)
        st.download_button(
            "Download Events CSV",
            data=events_df.to_csv(index=False).encode("utf-8"),
            file_name="threatlens_common_events.csv",
            mime="text/csv",
        )
        if "connector_id" in events_df.columns:
            distribution = (
                events_df["connector_id"]
                .value_counts()
                .rename_axis("Connector")
                .reset_index(name="Events")
            )
            st.plotly_chart(
                px.bar(distribution, x="Connector", y="Events", title="Events by Connector"),
                width="stretch",
            )
    with tabs[2]:
        if statistics:
            quality_metrics = st.columns(6)
            quality_metrics[0].metric("Sources", statistics.get("source_count", 0))
            quality_metrics[1].metric("Total Records", statistics.get("total_records", 0))
            quality_metrics[2].metric("Parsed", statistics.get("parsed_records", 0))
            quality_metrics[3].metric("Partial", statistics.get("partial_records", 0))
            quality_metrics[4].metric("Quarantined", statistics.get("quarantined_records", 0))
            quality_metrics[5].metric(
                "Success Rate",
                f"{statistics.get('parse_success_rate', 0) * 100:.1f}%",
            )
            st.json(statistics)
        if quarantined_df.empty:
            st.success("No records were quarantined.")
        else:
            st.dataframe(quarantined_df, width="stretch", hide_index=True)
            st.download_button(
                "Download Quarantine CSV",
                data=quarantined_df.to_csv(index=False).encode("utf-8"),
                file_name="threatlens_quarantine.csv",
                mime="text/csv",
            )
    with tabs[3]:
        if alerts_df.empty:
            st.info("No alerts were detected.")
        else:
            st.dataframe(alerts_df, width="stretch", hide_index=True)
            data = (
                alerts_df["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            st.plotly_chart(
                px.bar(data, x="Severity", y="Count", title="Alert Severity"),
                width="stretch",
            )
    with tabs[4]:
        if incidents_df.empty:
            st.info("No incidents were correlated.")
        else:
            st.dataframe(incidents_df, width="stretch", hide_index=True)
    with tabs[5]:
        if timeline_df.empty:
            st.info("No investigation timeline is available.")
        else:
            st.dataframe(timeline_df, width="stretch", hide_index=True)

    with tabs[6]:
        metrics = st.session_state.correlation_metrics
        if not metrics:
            st.info("Advanced correlation evidence is unavailable for this analysis.")
        else:
            correlation_metrics = st.columns(6)
            correlation_metrics[0].metric(
                "Representative Alerts", metrics.get("representative_alerts", 0)
            )
            correlation_metrics[1].metric("Deduplicated", metrics.get("deduplicated_alerts", 0))
            correlation_metrics[2].metric("Entities", metrics.get("entities", 0))
            correlation_metrics[3].metric("Relationships", metrics.get("relationships", 0))
            correlation_metrics[4].metric("Graph Nodes", metrics.get("graph_nodes", 0))
            correlation_metrics[5].metric("Graph Edges", metrics.get("graph_edges", 0))
            st.subheader("Resolved Entities")
            st.dataframe(
                st.session_state.correlation_entities_df,
                width="stretch",
                hide_index=True,
            )
            st.subheader("Scored Relationships")
            st.dataframe(
                st.session_state.correlation_relationships_df,
                width="stretch",
                hide_index=True,
            )
