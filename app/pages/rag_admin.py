from __future__ import annotations

import streamlit as st

from app.api_client import ApiClientError, ThreatLensApiClient


def render_rag_admin(client: ThreatLensApiClient) -> None:
    st.header("AI Knowledge Administration")
    st.caption(
        "Governed v0.11 adaptive RAG runtime and indexing. Deterministic detection/correlation "
        "remains independent "
        "from this subsystem. Reindexing never changes incident verdicts, risk scores "
        "or ATT&CK mappings."
    )
    permissions = set((st.session_state.authenticated_user or {}).get("permissions") or [])
    if "rag:manage" not in permissions:
        st.error("Your role cannot manage the RAG knowledge index.")
        return
    try:
        status = client.get_rag_knowledge_status()
    except ApiClientError as error:
        st.error(str(error))
        return
    health = status.get("health") or {}
    index = status.get("index") or {}
    profiles = {str(item.get("mode") or ""): item for item in (health.get("model_profiles") or [])}
    standard_profile = profiles.get("standard") or {}
    deep_profile = profiles.get("deep") or {}
    metrics = st.columns(6)
    metrics[0].metric("RAG Status", health.get("status", "unknown"))
    metrics[1].metric("Indexed Chunks", health.get("indexed_chunks", 0))
    metrics[2].metric("Knowledge Sources", index.get("source_count", 0))
    metrics[3].metric("Standard", standard_profile.get("model", health.get("llm_model", "n/a")))
    metrics[4].metric("Deep", deep_profile.get("model", "n/a"))
    metrics[5].metric("Embeddings", health.get("embedding_model", "unknown"))
    if health.get("details"):
        for detail in health["details"]:
            st.warning(detail)
    with st.expander("RAG runtime and index status", expanded=True):
        st.json(status)
    force = st.checkbox(
        "Force complete reindex",
        value=False,
        help=(
            "Normally ThreatLens performs incremental hash-based indexing and only "
            "re-embeds changed sources."
        ),
    )
    if st.button("Build / Refresh Governed Knowledge Index", type="primary"):
        try:
            result = client.reindex_rag_knowledge(force=force)
            if result.get("status") == "unavailable":
                st.error("The configured vector or embedding backend is unavailable.")
            else:
                st.success(
                    f"Knowledge index {result.get('status')}: "
                    f"{result.get('chunks_upserted', 0)} chunks upserted, "
                    f"{result.get('chunks_deleted', 0)} deleted."
                )
                st.json(result)
        except ApiClientError as error:
            st.error(str(error))
