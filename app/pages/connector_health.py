import streamlit as st

from app.api_client import ThreatLensApiClient


def render_connector_health(application_service: ThreatLensApiClient) -> None:
    st.header("Connector Health and Coverage")
    st.caption(
        "Registered telemetry adapters, parser versions, supported formats and "
        "validated rule coverage."
    )
    catalog = application_service.get_connector_catalog()
    if catalog.empty:
        st.error("No connectors are registered.")
        return

    metrics = st.columns(4)
    metrics[0].metric("Registered Connectors", len(catalog))
    metrics[1].metric("Products", int(catalog["product"].nunique()))
    metrics[2].metric("Connector Rules", int(catalog["rule_count"].sum()))
    metrics[3].metric("Operational", int((catalog["status"] == "registered").sum()))

    st.dataframe(catalog, width="stretch", hide_index=True)

    st.subheader("Coverage by Connector")
    coverage = catalog[["connector_id", "name", "product", "service", "rule_count"]].copy()
    coverage["coverage_state"] = coverage["rule_count"].map(
        lambda count: "Rules available" if count > 0 else "Parser only"
    )
    st.dataframe(coverage, width="stretch", hide_index=True)

    st.info(
        "Connector registration proves ingestion and normalization support. Detection "
        "coverage is reported separately because a parser does not automatically imply "
        "complete ATT&CK coverage."
    )
