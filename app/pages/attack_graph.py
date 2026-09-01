from __future__ import annotations

import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.api_client import ThreatLensApiClient
from correlation.export import attack_graph_export_json

NODE_SYMBOLS = {
    "incident": "diamond",
    "alert": "circle",
    "entity": "square",
    "technique": "hexagon",
    "tactic": "triangle-up",
}


def render_attack_graph(application_service: ThreatLensApiClient) -> None:
    st.header("Advanced Correlation and Attack Graph")
    st.caption(
        "Cross-source entity resolution, semantic alert deduplication, explainable "
        "relationship confidence, ordered ATT&CK stages and persistent graph evidence."
    )

    history = application_service.get_analysis_history(limit=250)
    if history.empty:
        st.info("No persisted analyses are available for graph investigation.")
        return

    current = st.session_state.get("current_session_uuid")
    options = history["session_uuid"].astype(str).tolist()
    default_index = options.index(current) if current in options else 0
    session_uuid = st.selectbox(
        "Analysis session",
        options=options,
        index=default_index,
        format_func=lambda value: _session_label(history, value),
    )

    summary = application_service.get_correlation_summary(session_uuid)
    graph = application_service.get_attack_graph(session_uuid)
    entities = application_service.get_correlation_entities(session_uuid)
    relationships = application_service.get_correlation_relationships(session_uuid)
    pipeline = application_service.load_analysis(session_uuid)

    if not summary or not graph:
        st.warning(
            "This analysis predates v0.8 correlation persistence. Re-run the source "
            "under the v0.8 engine to generate an attack graph."
        )
        return

    metrics = summary.get("metrics") or {}
    metric_columns = st.columns(8)
    metric_columns[0].metric("Input Alerts", metrics.get("input_alerts", 0))
    metric_columns[1].metric("Representative Alerts", metrics.get("representative_alerts", 0))
    metric_columns[2].metric("Deduplicated", metrics.get("deduplicated_alerts", 0))
    metric_columns[3].metric("Entities", metrics.get("entities", 0))
    metric_columns[4].metric("Relationships", metrics.get("relationships", 0))
    metric_columns[5].metric("Incidents", metrics.get("incidents", 0))
    metric_columns[6].metric("Graph Nodes", metrics.get("graph_nodes", 0))
    metric_columns[7].metric("Graph Edges", metrics.get("graph_edges", 0))

    st.caption(
        f"Correlation version: {summary.get('version')} | "
        f"Graph SHA-256: {summary.get('graph_sha256')}"
    )

    nodes = pd.DataFrame(graph.get("nodes") or [])
    edges = pd.DataFrame(graph.get("edges") or [])
    if nodes.empty:
        st.warning("The persisted graph contains no nodes.")
        return

    node_types = sorted(nodes["node_type"].dropna().astype(str).unique().tolist())
    selected_types = st.multiselect(
        "Node layers",
        options=node_types,
        default=node_types,
    )
    confidence_threshold = st.slider(
        "Minimum displayed relationship confidence",
        min_value=0.0,
        max_value=1.0,
        value=0.40,
        step=0.05,
    )
    incident_options = sorted(
        int(value) for value in nodes["incident_id"].dropna().unique().tolist()
    )
    selected_incidents = st.multiselect(
        "Incident filter",
        options=incident_options,
        default=incident_options,
    )

    filtered_nodes = nodes[nodes["node_type"].isin(selected_types)].copy()
    if selected_incidents:
        filtered_nodes = filtered_nodes[
            filtered_nodes["incident_id"].isna()
            | filtered_nodes["incident_id"].isin(selected_incidents)
        ]
    node_ids = set(filtered_nodes["node_id"].astype(str))
    filtered_edges = edges[
        edges["source"].astype(str).isin(node_ids)
        & edges["target"].astype(str).isin(node_ids)
        & (pd.to_numeric(edges["confidence"], errors="coerce") >= confidence_threshold)
    ].copy()

    tabs = st.tabs(
        [
            "Interactive Graph",
            "Resolved Entities",
            "Scored Relationships",
            "Incident Storylines",
            "Exports",
        ]
    )
    with tabs[0]:
        st.plotly_chart(
            _graph_figure(filtered_nodes, filtered_edges),
            width="stretch",
            config={"displaylogo": False, "scrollZoom": True},
        )
        st.caption(
            f"Showing {len(filtered_nodes)} nodes and {len(filtered_edges)} edges. "
            "Edge confidence and reasons remain available in the relationship table."
        )

    with tabs[1]:
        if entities.empty:
            st.info("No resolved entities are available.")
        else:
            entity_types = sorted(entities["entity_type"].dropna().unique().tolist())
            selected_entity_types = st.multiselect(
                "Entity types",
                entity_types,
                default=entity_types,
                key="attack_graph_entity_types",
            )
            entity_view = entities[entities["entity_type"].isin(selected_entity_types)]
            st.dataframe(entity_view, width="stretch", hide_index=True)

    with tabs[2]:
        if relationships.empty:
            st.info("No scored alert relationships are available.")
        else:
            relationship_view = relationships.copy()
            relationship_view = relationship_view[
                pd.to_numeric(relationship_view["confidence"], errors="coerce")
                >= confidence_threshold
            ]
            st.dataframe(relationship_view, width="stretch", hide_index=True)

    with tabs[3]:
        incidents = pipeline.incidents_df if pipeline is not None else pd.DataFrame()
        if incidents.empty:
            st.info("No incident storylines are available.")
        else:
            columns = [
                column
                for column in (
                    "incident_uuid",
                    "incident_name",
                    "severity",
                    "risk_score",
                    "confidence",
                    "source_count",
                    "entity_count",
                    "relationship_count",
                    "stage_progression",
                    "graph_score",
                    "storyline",
                )
                if column in incidents.columns
            ]
            st.dataframe(incidents[columns], width="stretch", hide_index=True)

    with tabs[4]:
        graph_bytes = attack_graph_export_json(
            graph,
            session_uuid=session_uuid,
            correlation_uuid=summary.get("correlation_uuid"),
            graph_sha256=summary.get("graph_sha256"),
        )
        st.download_button(
            "Download Attack Graph JSON",
            data=graph_bytes,
            file_name=f"threatlens_attack_graph_{session_uuid}.json",
            mime="application/json",
        )
        st.download_button(
            "Download Graph Nodes CSV",
            data=nodes.to_csv(index=False).encode("utf-8"),
            file_name=f"threatlens_graph_nodes_{session_uuid}.csv",
            mime="text/csv",
        )
        st.download_button(
            "Download Graph Edges CSV",
            data=edges.to_csv(index=False).encode("utf-8"),
            file_name=f"threatlens_graph_edges_{session_uuid}.csv",
            mime="text/csv",
        )
        if not entities.empty:
            st.download_button(
                "Download Resolved Entities CSV",
                data=entities.to_csv(index=False).encode("utf-8"),
                file_name=f"threatlens_entities_{session_uuid}.csv",
                mime="text/csv",
            )
        if not relationships.empty:
            st.download_button(
                "Download Scored Relationships CSV",
                data=relationships.to_csv(index=False).encode("utf-8"),
                file_name=f"threatlens_relationships_{session_uuid}.csv",
                mime="text/csv",
            )


def _session_label(history: pd.DataFrame, session_uuid: str) -> str:
    row = history[history["session_uuid"] == session_uuid]
    if row.empty:
        return session_uuid
    item = row.iloc[0]
    return f"{item.get('name', 'Analysis')} | {item.get('created_at')} | {session_uuid[:8]}"


def _graph_figure(nodes: pd.DataFrame, edges: pd.DataFrame) -> go.Figure:
    positions = {
        str(row["node_id"]): (float(row["x"]), float(row["y"])) for _, row in nodes.iterrows()
    }
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    edge_hover: list[str | None] = []
    for _, edge in edges.iterrows():
        source = positions.get(str(edge.get("source")))
        target = positions.get(str(edge.get("target")))
        if source is None or target is None:
            continue
        label = (
            f"{edge.get('relationship_type')}<br>"
            f"confidence={float(edge.get('confidence') or 0):.2f}<br>"
            f"{'; '.join(str(item) for item in (edge.get('reasons') or []))}"
        )
        edge_x.extend([source[0], target[0], None])
        edge_y.extend([source[1], target[1], None])
        edge_hover.extend([label, label, None])

    figure = go.Figure()
    figure.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            line={"width": 1},
            hoverinfo="text",
            text=edge_hover,
            name="Relationships",
        )
    )
    for node_type, group in nodes.groupby("node_type", sort=True):
        hover = []
        for _, row in group.iterrows():
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            hover.append(
                f"{row.get('label')}<br>type={node_type}<br>"
                f"subtype={row.get('subtype')}<br>"
                f"confidence={float(row.get('confidence') or 0):.2f}<br>"
                f"{json.dumps(metadata, default=str)}"
            )
        figure.add_trace(
            go.Scatter(
                x=group["x"],
                y=group["y"],
                mode="markers+text",
                text=group["label"],
                textposition="top center",
                hovertext=hover,
                hoverinfo="text",
                marker={
                    "size": 17 if node_type == "incident" else 12,
                    "symbol": NODE_SYMBOLS.get(str(node_type), "circle"),
                    "line": {"width": 1},
                },
                name=str(node_type).title(),
            )
        )
    figure.update_layout(
        title="ThreatLens Layered Attack Graph",
        showlegend=True,
        hovermode="closest",
        margin={"l": 20, "r": 20, "t": 60, "b": 20},
        xaxis={
            "visible": False,
            "range": [-0.5, 4.5],
        },
        yaxis={"visible": False},
        height=760,
    )
    return figure
