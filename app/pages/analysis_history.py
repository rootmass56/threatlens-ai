import pandas as pd
import streamlit as st

from app.api_client import ThreatLensApiClient
from app.state import store_loaded_analysis


def render_analysis_history(application_service: ThreatLensApiClient) -> None:
    st.header("Analysis History")
    history_df = application_service.get_analysis_history(limit=1000)
    if history_df.empty:
        st.info("No persisted analysis sessions are available.")
        return

    source_types = sorted(history_df["source_type"].dropna().unique().tolist())
    statuses = sorted(history_df["status"].dropna().unique().tolist())
    filters = st.columns(3)
    selected_sources = filters[0].multiselect("Source type", source_types, default=source_types)
    selected_statuses = filters[1].multiselect("Status", statuses, default=statuses)
    filename_search = filters[2].text_input("Filename contains")

    filtered = history_df[
        history_df["source_type"].isin(selected_sources)
        & history_df["status"].isin(selected_statuses)
    ].copy()
    if filename_search:
        filtered = filtered[
            filtered["filename"].fillna("").str.contains(filename_search, case=False, regex=False)
        ]
    for column in ("started_at", "completed_at", "created_at"):
        if column in filtered.columns:
            filtered[column] = pd.to_datetime(filtered[column], errors="coerce")

    st.metric("Matching Sessions", len(filtered))
    st.dataframe(filtered, width="stretch", hide_index=True)
    st.download_button(
        "Download History CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="threatlens_analysis_history.csv",
        mime="text/csv",
    )

    if filtered.empty:
        return
    options = filtered["session_uuid"].tolist()
    selected_uuid = st.selectbox(
        "Reload a persisted analysis",
        options=options,
        format_func=lambda uuid: (
            f"{filtered.loc[filtered['session_uuid'] == uuid, 'name'].iloc[0]} — {uuid}"
        ),
    )
    if st.button("Load Selected Analysis", type="primary"):
        pipeline = application_service.load_analysis(selected_uuid)
        metadata = application_service.get_analysis_metadata(selected_uuid)
        if pipeline is None or metadata is None:
            st.error("The selected analysis could not be loaded.")
        else:
            store_loaded_analysis(
                pipeline,
                session_uuid=selected_uuid,
                analysis_name=metadata.get("name"),
                filename=metadata.get("filename"),
            )
            st.success("Persistent analysis reloaded into the current workspace.")
