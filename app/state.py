import pandas as pd
import streamlit as st

from app.application_service import AnalysisExecutionResult
from core.pipeline import AnalysisPipelineResult

DATAFRAME_STATE_KEYS = (
    "events_df",
    "alerts_df",
    "incidents_df",
    "timeline_df",
    "quarantined_df",
    "source_manifest_df",
    "correlation_entities_df",
    "correlation_relationships_df",
    "attack_graph_nodes_df",
    "attack_graph_edges_df",
)


def initialize_application_state() -> None:
    for key in DATAFRAME_STATE_KEYS:
        if key not in st.session_state:
            st.session_state[key] = pd.DataFrame()
    defaults = {
        "current_session_uuid": None,
        "duplicate_session_uuid": None,
        "current_analysis_name": None,
        "current_filename": None,
        "current_connector_id": None,
        "current_connector_ids": [],
        "parser_statistics": {},
        "loaded_rule_count": None,
        "current_quarantined_count": 0,
        "correlation_metrics": {},
        "selected_incident_uuid": None,
        "requested_page": None,
        "analyst_identity": "unknown",
        "report_bytes": None,
        "report_filename": None,
        "report_sha256": None,
        "api_access_token": None,
        "api_refresh_token": None,
        "authenticated_user": {},
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _store_pipeline(
    pipeline: AnalysisPipelineResult,
    *,
    session_uuid: str | None,
    analysis_name: str | None,
    filename: str | None,
) -> None:
    st.session_state.events_df = pipeline.events_df
    st.session_state.alerts_df = pipeline.alerts_df
    st.session_state.incidents_df = pipeline.incidents_df
    st.session_state.timeline_df = pipeline.timeline_df
    st.session_state.quarantined_df = pipeline.quarantined_dataframe()
    st.session_state.current_quarantined_count = int(pipeline.quarantined_count)
    st.session_state.source_manifest_df = pd.DataFrame(pipeline.source_manifest)
    st.session_state.parser_statistics = pipeline.combined_parser_statistics()
    st.session_state.current_connector_id = pipeline.connector_id
    st.session_state.current_connector_ids = list(pipeline.connector_ids)
    remote_rule_count = getattr(pipeline, "loaded_rule_count", None)
    st.session_state.loaded_rule_count = (
        int(remote_rule_count)
        if remote_rule_count is not None
        else (
            len(pipeline.rule_validation.enabled_rules)
            if pipeline.rule_validation is not None
            else None
        )
    )
    correlation = pipeline.correlation_result
    st.session_state.correlation_entities_df = (
        correlation.entities_df if correlation is not None else pd.DataFrame()
    )
    st.session_state.correlation_relationships_df = (
        correlation.relationships_df if correlation is not None else pd.DataFrame()
    )
    st.session_state.attack_graph_nodes_df = (
        correlation.graph_nodes_df if correlation is not None else pd.DataFrame()
    )
    st.session_state.attack_graph_edges_df = (
        correlation.graph_edges_df if correlation is not None else pd.DataFrame()
    )
    st.session_state.correlation_metrics = (
        dict(correlation.metrics) if correlation is not None else {}
    )
    st.session_state.current_session_uuid = session_uuid
    st.session_state.current_analysis_name = analysis_name
    st.session_state.current_filename = filename
    st.session_state.report_bytes = None
    st.session_state.report_filename = None


def store_analysis_result(
    execution_result: AnalysisExecutionResult,
    *,
    analysis_name: str,
    filename: str | None,
) -> None:
    _store_pipeline(
        execution_result.pipeline,
        session_uuid=execution_result.session_uuid,
        analysis_name=analysis_name,
        filename=filename,
    )
    st.session_state.duplicate_session_uuid = execution_result.duplicate_session_uuid


def store_loaded_analysis(
    pipeline: AnalysisPipelineResult,
    *,
    session_uuid: str,
    analysis_name: str | None,
    filename: str | None,
) -> None:
    _store_pipeline(
        pipeline,
        session_uuid=session_uuid,
        analysis_name=analysis_name,
        filename=filename,
    )
    st.session_state.duplicate_session_uuid = None


def clear_current_analysis() -> None:
    for key in DATAFRAME_STATE_KEYS:
        st.session_state[key] = pd.DataFrame()
    for key in (
        "current_session_uuid",
        "duplicate_session_uuid",
        "current_analysis_name",
        "current_filename",
        "current_connector_id",
        "selected_incident_uuid",
        "report_bytes",
        "report_filename",
        "report_sha256",
    ):
        st.session_state[key] = None
    st.session_state.current_connector_ids = []
    st.session_state.parser_statistics = {}
    st.session_state.loaded_rule_count = None
    st.session_state.current_quarantined_count = 0
    st.session_state.correlation_metrics = {}
