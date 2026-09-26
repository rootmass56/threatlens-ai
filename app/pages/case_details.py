import hashlib
import json

import pandas as pd
import streamlit as st

from app.api_client import ThreatLensApiClient
from app.case_policy import case_capabilities
from app.state import store_loaded_analysis
from app.upload_limits import enforce_file_size, streamlit_upload_limit_mb

PRIORITY_OPTIONS = ["P1", "P2", "P3", "P4"]
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024


def _incident_selector(application_service: ThreatLensApiClient) -> str | None:
    queue = application_service.get_incident_queue(limit=1000)
    if queue.empty:
        return None
    options = queue["incident_uuid"].tolist()
    if st.session_state.get("selected_incident_uuid") not in options:
        st.session_state.selected_incident_uuid = options[0]
    return st.selectbox(
        "Incident",
        options=options,
        key="selected_incident_uuid",
        format_func=lambda uuid: (
            f"{queue.loc[queue['incident_uuid'] == uuid, 'title'].iloc[0]} — {uuid}"
        ),
    )


def _synchronize_analysis_context(
    application_service: ThreatLensApiClient,
    details: dict,
) -> None:
    """Keep sidebar/current-analysis state aligned with the incident being investigated."""

    session_uuid = str(details.get("analysis_session_uuid") or "").strip()
    if not session_uuid or st.session_state.current_session_uuid == session_uuid:
        return
    pipeline = application_service.load_analysis(session_uuid)
    metadata = application_service.get_analysis_metadata(session_uuid)
    if pipeline is None or metadata is None:
        return
    store_loaded_analysis(
        pipeline,
        session_uuid=session_uuid,
        analysis_name=str(metadata.get("name") or "ThreatLens analysis"),
        filename=metadata.get("filename"),
    )
    st.rerun()


def _evidence_upload_limit(application_service: ThreatLensApiClient) -> int:
    status = application_service.security_status()
    limits = status.get("upload_limits") or {}
    return max(int(limits.get("max_file_bytes") or DEFAULT_MAX_FILE_BYTES), 1)


def _read_only_workflow(incident: dict) -> None:
    columns = st.columns(3)
    columns[0].markdown(f"**Status**  \n{incident.get('status') or 'open'}")
    columns[1].markdown(f"**Priority**  \n{incident.get('priority') or 'P3'}")
    columns[2].markdown(f"**Assignee**  \n{incident.get('assignee') or 'Unassigned'}")
    st.caption("Read-only workflow access for this account/case.")


def render_case_details(application_service: ThreatLensApiClient) -> None:
    st.header("Incident Case Workspace")
    incident_uuid = _incident_selector(application_service)
    if incident_uuid is None:
        st.info("No incident cases are available.")
        return
    details = application_service.get_incident_details(incident_uuid)
    if details is None:
        st.error("The incident could not be loaded.")
        return

    _synchronize_analysis_context(application_service, details)

    incident = details["incident"]
    user = st.session_state.authenticated_user or application_service.user
    capabilities = case_capabilities(user, incident)
    username = str(user.get("username") or "").strip()

    metrics = st.columns(6)
    metrics[0].metric("Severity", incident["severity"])
    metrics[1].metric("Risk", incident["risk_score"])
    metrics[2].metric("Confidence", f"{incident['confidence']:.0%}")
    metrics[3].metric("Priority", incident["priority"])
    metrics[4].metric("Alerts", incident["alert_count"])
    metrics[5].metric("Graph Score", f"{float(incident.get('graph_score') or 0):.2f}")

    st.subheader(incident["incident_name"])
    st.write(incident["summary"])
    if incident.get("storyline"):
        st.info(incident["storyline"])
    st.caption(f"Incident UUID: {incident_uuid}")
    st.caption(f"Analysis UUID: {details['analysis_session_uuid']}")
    st.caption(
        "Correlation: "
        f"{incident.get('correlation_version') or 'legacy'} | "
        f"ID {incident.get('correlation_id') or 'not available'}"
    )

    graph_metrics = st.columns(5)
    graph_metrics[0].metric("Sources", int(incident.get("source_count") or 0))
    graph_metrics[1].metric("Entities", int(incident.get("entity_count") or 0))
    graph_metrics[2].metric("Relationships", int(incident.get("relationship_count") or 0))
    graph_metrics[3].metric("ATT&CK Stages", int(incident.get("stage_count") or 0))
    graph_metrics[4].metric("Deduplicated", int(incident.get("deduplicated_alert_count") or 0))
    if incident.get("stage_progression"):
        st.markdown(f"**ATT&CK stage progression:** {incident['stage_progression']}")

    (
        workflow_tab,
        alerts_tab,
        correlation_tab,
        evidence_tab,
        notes_tab,
        assistant_tab,
        audit_tab,
    ) = st.tabs(
        [
            "Workflow",
            "Alerts and Events",
            "Correlation Evidence",
            "Evidence",
            "Notes",
            "AI Assistant",
            "Case Audit",
        ]
    )

    with workflow_tab:
        if not capabilities.can_update:
            _read_only_workflow(incident)
        else:
            status_options = list(capabilities.status_options) or [incident["status"]]
            status_index = (
                status_options.index(incident["status"])
                if incident["status"] in status_options
                else 0
            )
            priority_index = (
                PRIORITY_OPTIONS.index(incident["priority"])
                if incident["priority"] in PRIORITY_OPTIONS
                else 2
            )
            with st.form("workflow_form"):
                status = st.selectbox("Status", status_options, index=status_index)
                priority = st.selectbox("Priority", PRIORITY_OPTIONS, index=priority_index)
                current_assignee = str(incident.get("assignee") or "").strip()
                if capabilities.can_assign_any:
                    assignee = st.text_input(
                        "Assignee",
                        value=current_assignee,
                        max_chars=64,
                        help="Assignee must be an active investigator-eligible ThreatLens user.",
                    )
                elif not current_assignee and username:
                    assign_self = st.checkbox("Assign this case to me", value=False)
                    assignee = username if assign_self else None
                else:
                    st.markdown(f"**Assignee:** {current_assignee or 'Unassigned'}")
                    assignee = current_assignee or None
                submitted = st.form_submit_button("Update Case", type="primary")
            if submitted:
                current_state = {
                    "status": str(incident.get("status") or "open").strip().lower(),
                    "priority": str(incident.get("priority") or "P3").strip().upper(),
                    "assignee": str(incident.get("assignee") or "").strip() or None,
                }
                requested_state = {
                    "status": str(status).strip().lower(),
                    "priority": str(priority).strip().upper(),
                    "assignee": str(assignee or "").strip() or None,
                }
                if requested_state == current_state:
                    st.info(
                        "No changes detected. Case workflow was not modified and no audit "
                        "record was created."
                    )
                else:
                    try:
                        application_service.update_incident(
                            incident_uuid=incident_uuid,
                            status=status,
                            assignee=assignee,
                            priority=priority,
                            actor=st.session_state.analyst_identity.strip() or "unknown",
                        )
                        st.success(
                            "Case workflow updated successfully. The state change was recorded "
                            "in the case audit trail."
                        )
                        st.rerun()
                    except Exception as error:
                        st.error(str(error))

    with alerts_tab:
        alerts_df = pd.DataFrame(details["alerts"])
        events_df = pd.DataFrame(details["events"])
        st.markdown("#### Related Alerts")
        st.dataframe(alerts_df, width="stretch", hide_index=True)
        st.markdown("#### Supporting Events")
        st.dataframe(events_df, width="stretch", hide_index=True)

    with correlation_tab:
        entities_df = pd.DataFrame(details.get("correlation_entities") or [])
        relationships_df = pd.DataFrame(details.get("correlation_relationships") or [])
        st.markdown("#### Resolved Incident Entities")
        if entities_df.empty:
            st.info("No v0.8 correlation entities are attached to this incident.")
        else:
            entity_columns = [
                column
                for column in (
                    "entity_type",
                    "display_value",
                    "confidence",
                    "source_datasets",
                    "evidence_alert_ids",
                    "first_seen",
                    "last_seen",
                )
                if column in entities_df.columns
            ]
            st.dataframe(entities_df[entity_columns], width="stretch", hide_index=True)

        st.markdown("#### Explainable Alert Relationships")
        if relationships_df.empty:
            st.info("No scored v0.8 relationships are attached to this incident.")
        else:
            relationship_columns = [
                column
                for column in (
                    "source_node_key",
                    "target_node_key",
                    "relationship_type",
                    "confidence",
                    "shared_entity_count",
                    "cluster_eligible",
                    "time_delta_seconds",
                    "reasons",
                    "shared_entities",
                )
                if column in relationships_df.columns
            ]
            st.dataframe(
                relationships_df[relationship_columns],
                width="stretch",
                hide_index=True,
            )

        st.caption(
            "Correlation relationships are deterministic and evidence-backed. "
            "Semantic duplicates reduce correlation noise without deleting original alerts."
        )

    with evidence_tab:
        existing = pd.DataFrame(details["evidence"])
        if existing.empty:
            st.info("No evidence metadata has been registered.")
        else:
            st.dataframe(existing, width="stretch", hide_index=True)
        if capabilities.can_add_evidence:
            max_file_bytes = _evidence_upload_limit(application_service)
            widget_limit_mb = streamlit_upload_limit_mb(max_file_bytes)
            st.caption(
                "Evidence API boundary: "
                f"{max_file_bytes / (1024 * 1024):.1f} MiB "
                f"({max_file_bytes:,} bytes) per file. The browser control may display "
                f"{widget_limit_mb} MB because Streamlit uses decimal MB for its transport "
                "cap; ThreatLens still enforces the exact API byte limit before hashing "
                "or submission."
            )
            with st.form("evidence_form", clear_on_submit=True):
                evidence_type = st.selectbox(
                    "Evidence type", ["log_file", "screenshot", "export", "hash", "other"]
                )
                description = st.text_area("Description", max_chars=10_000)
                source_reference = st.text_input("Source reference", max_chars=1024)
                uploaded = st.file_uploader(
                    "Optional evidence file for SHA-256 calculation",
                    max_upload_size=widget_limit_mb,
                    help=(
                        "The file is hashed in the UI; only evidence metadata is sent to "
                        "FastAPI. The browser transport cap is rounded up only so it never "
                        "rejects a file that is valid under the exact API byte boundary."
                    ),
                )
                supplied_hash = st.text_input(
                    "SHA-256 (optional when file is uploaded)", max_chars=64
                )
                add_evidence = st.form_submit_button("Register Evidence")
            if add_evidence:
                calculated_hash = supplied_hash.strip() or None
                try:
                    if uploaded is not None:
                        payload = uploaded.getvalue()
                        enforce_file_size(
                            len(payload),
                            max_file_bytes,
                            label=uploaded.name or "Evidence file",
                        )
                        calculated_hash = hashlib.sha256(payload).hexdigest()
                    reference = source_reference.strip()
                    if not reference and uploaded is not None:
                        reference = uploaded.name
                    application_service.register_incident_evidence(
                        incident_uuid=incident_uuid,
                        evidence_type=evidence_type,
                        description=description,
                        source_reference=reference or None,
                        sha256=calculated_hash,
                        actor=st.session_state.analyst_identity.strip() or "unknown",
                    )
                    st.success("Evidence metadata registered and audited.")
                    st.rerun()
                except Exception as error:
                    st.error(str(error))
        else:
            st.info("Read-only evidence access for this account/case.")

    with notes_tab:
        notes_df = pd.DataFrame(details["notes"])
        if notes_df.empty:
            st.info("No analyst notes are available.")
        else:
            st.dataframe(notes_df, width="stretch", hide_index=True)
        if capabilities.can_add_note:
            with st.form("note_form", clear_on_submit=True):
                note = st.text_area("Investigation note", max_chars=10_000)
                add_note = st.form_submit_button("Add Note")
            if add_note:
                try:
                    application_service.add_incident_note(
                        incident_uuid=incident_uuid,
                        author=st.session_state.analyst_identity.strip() or "unknown",
                        note=note,
                    )
                    st.success("Investigation note added and audited.")
                    st.rerun()
                except Exception as error:
                    st.error(str(error))
        else:
            st.info("Read-only note access for this account/case.")

    with assistant_tab:
        st.markdown("#### Grounded AI Investigation Assistant")
        st.caption(
            "ThreatLens deterministic detections, incident scoring and ATT&CK mappings remain "
            "authoritative. The assistant can only explain the authorized persisted incident "
            "evidence and governed indexed security knowledge, with citations and limitations."
        )
        try:
            health = application_service.get_rag_health()
        except Exception as error:
            health = {"status": "unavailable", "details": [str(error)]}
        profiles = {
            str(item.get("mode") or ""): item for item in (health.get("model_profiles") or [])
        }
        standard_profile = profiles.get("standard") or {}
        deep_profile = profiles.get("deep") or {}
        health_columns = st.columns(5)
        health_columns[0].metric("Assistant", str(health.get("status") or "unknown"))
        health_columns[1].metric("Indexed chunks", int(health.get("indexed_chunks") or 0))
        health_columns[2].metric(
            "Standard", str(standard_profile.get("model") or health.get("llm_model") or "n/a")
        )
        health_columns[3].metric("Deep", str(deep_profile.get("model") or "n/a"))
        health_columns[4].metric(
            "Embeddings", str(health.get("embedding_model") or "not configured")
        )
        if deep_profile and not deep_profile.get("available"):
            st.info(
                "Deep Analysis is currently unavailable. Auto mode can transparently fall "
                "back to the Standard profile when configured."
            )
        for detail in health.get("details") or []:
            st.warning(str(detail))

        prompt_examples = (
            "Why is this incident considered critical?",
            "Which persisted evidence supports the ATT&CK progression?",
            "What should I investigate next, based only on the available evidence?",
        )
        selected_example = st.selectbox(
            "Investigation prompt example",
            options=("Write my own question", *prompt_examples),
            key=f"rag_example_{incident_uuid}",
        )
        default_question = "" if selected_example == "Write my own question" else selected_example
        with st.form(f"rag_query_form_{incident_uuid}"):
            analysis_mode = st.radio(
                "Analysis mode",
                options=("auto", "standard", "deep"),
                index=0,
                horizontal=True,
                format_func=lambda value: {
                    "auto": "Auto — Recommended",
                    "standard": "Standard — Qwen3.5:4B",
                    "deep": "Deep Analysis — Qwen3.5:9B",
                }[value],
                help=(
                    "Auto uses a deterministic complexity router. Standard prioritizes lower "
                    "latency. Deep uses the higher-capacity local model with a larger output "
                    "budget. Both use the same evidence, security and grounding controls."
                ),
            )
            question = st.text_area(
                "Question",
                value=default_question,
                max_chars=2000,
                height=100,
                help=(
                    "Questions are incident-scoped. Retrieved documents are treated as untrusted "
                    "data and cannot override ThreatLens security policy."
                ),
            )
            ask = st.form_submit_button("Ask Grounded Assistant", type="primary")
        if ask:
            if not question.strip():
                st.warning("Enter an investigation question.")
            else:
                try:
                    with st.spinner(
                        "Routing the investigation, retrieving authorized evidence and "
                        "running grounded analysis..."
                    ):
                        response = application_service.query_incident_assistant(
                            incident_uuid,
                            question.strip(),
                            analysis_mode=analysis_mode,
                        )
                    st.session_state[f"rag_response_{incident_uuid}"] = response
                except Exception as error:
                    st.error(str(error))

        response = st.session_state.get(f"rag_response_{incident_uuid}")
        if response:
            status_value = str(response.get("status") or "unknown")
            grounding_score = float(response.get("grounding_score") or 0.0)
            result_columns = st.columns(4)
            result_columns[0].metric("Grounding status", status_value)
            result_columns[1].metric("Grounding score", f"{grounding_score:.0%}")
            result_columns[2].metric(
                "Accepted retrievals",
                int((response.get("retrieval") or {}).get("accepted_count") or 0),
            )
            result_columns[3].metric(
                "Latency", f"{float(response.get('total_latency_ms') or 0):.0f} ms"
            )
            requested_mode = str(response.get("requested_mode") or "auto")
            resolved_mode = str(response.get("resolved_mode") or "not invoked")
            served_model = str(response.get("served_model") or "model not invoked")
            generation_ms = float(response.get("generation_latency_ms") or 0.0)
            st.caption(
                f"Requested mode: {requested_mode} · Resolved mode: {resolved_mode} · "
                f"Served model: {served_model} · Generation: {generation_ms:.0f} ms"
            )
            if response.get("fallback_used"):
                st.warning(
                    "Model fallback used: "
                    + str(
                        response.get("fallback_reason")
                        or (
                            "Deep Analysis could not complete; the answer was regenerated "
                            "with Standard and grounding was revalidated."
                        )
                    )
                )
            st.markdown("##### Assessment")
            st.write(response.get("assessment") or "No assessment was returned.")
            assessment_citations = response.get("assessment_citation_ids") or []
            if assessment_citations:
                st.caption(
                    "Assessment citations: " + ", ".join(str(item) for item in assessment_citations)
                )
            findings = response.get("key_findings") or []
            if findings:
                st.markdown("##### Key findings")
                for item in findings:
                    text = str(item.get("text") or "")
                    citation_ids = item.get("citation_ids") or []
                    suffix = (
                        " — " + ", ".join(str(value) for value in citation_ids)
                        if citation_ids
                        else " — unsupported"
                    )
                    st.markdown(f"- {text}{suffix}")
            technique_explanations = response.get("technique_explanations") or []
            if technique_explanations:
                st.markdown("##### ATT&CK evidence vs governed knowledge")
                for item in technique_explanations:
                    technique_id = str(item.get("technique_id") or "")
                    technique_name = str(item.get("technique_name") or "").strip()
                    heading = (
                        f"{technique_id} — {technique_name}" if technique_name else technique_id
                    )
                    with st.expander(heading, expanded=True):
                        st.markdown("**Observed persisted evidence**")
                        st.write(item.get("observed_evidence") or "No supported evidence summary.")
                        evidence_ids = item.get("evidence_citation_ids") or []
                        if evidence_ids:
                            st.caption(
                                "Evidence citations: "
                                + ", ".join(str(value) for value in evidence_ids)
                            )
                        st.markdown("**Governed ATT&CK / rule knowledge**")
                        st.write(
                            item.get("governed_explanation") or "No governed knowledge explanation."
                        )
                        knowledge_ids = item.get("knowledge_citation_ids") or []
                        if knowledge_ids:
                            st.caption(
                                "Knowledge citations: "
                                + ", ".join(str(value) for value in knowledge_ids)
                            )
                        analyst_inference = str(item.get("analyst_inference") or "").strip()
                        if analyst_inference:
                            st.markdown("**Analyst inference (bounded synthesis)**")
                            st.write(analyst_inference)

            actions = response.get("recommended_actions") or []
            if actions:
                st.markdown("##### Recommended investigation / response actions")
                for item in actions:
                    text = str(item.get("text") or "")
                    citation_ids = item.get("citation_ids") or []
                    suffix = (
                        " — " + ", ".join(str(value) for value in citation_ids)
                        if citation_ids
                        else " — unsupported"
                    )
                    st.markdown(f"- {text}{suffix}")
            limitations = response.get("limitations") or []
            if limitations:
                st.markdown("##### Limitations")
                for item in limitations:
                    st.warning(str(item))
            citations = pd.DataFrame(response.get("citations") or [])
            st.markdown("##### Grounding citations")
            if citations.empty:
                st.info("No validated citations were returned.")
            else:
                display_columns = [
                    column
                    for column in (
                        "citation_id",
                        "source_type",
                        "title",
                        "snippet",
                        "source_reference",
                        "relevance",
                    )
                    if column in citations.columns
                ]
                st.dataframe(citations[display_columns], width="stretch", hide_index=True)
            with st.expander("Assistant diagnostics"):
                st.json(
                    {
                        "query_uuid": response.get("query_uuid"),
                        "status": response.get("status"),
                        "retrieval": response.get("retrieval"),
                        "query_plan": response.get("query_plan"),
                        "requested_mode": response.get("requested_mode"),
                        "resolved_mode": response.get("resolved_mode"),
                        "requested_model": response.get("requested_model"),
                        "served_model": response.get("served_model"),
                        "fallback_used": response.get("fallback_used"),
                        "fallback_reason": response.get("fallback_reason"),
                        "routing_reasons": response.get("routing_reasons"),
                        "routing_score": response.get("routing_score"),
                        "generation_latency_ms": response.get("generation_latency_ms"),
                        "llm_model": response.get("llm_model"),
                        "embedding_model": response.get("embedding_model"),
                        "knowledge_version": response.get("knowledge_version"),
                        "unsupported_citation_ids": response.get("unsupported_citation_ids"),
                    }
                )

        st.markdown("##### Previous assistant queries for this incident")
        try:
            history_df = application_service.get_incident_assistant_history(incident_uuid, limit=25)
        except Exception as error:
            st.warning(f"Assistant history could not be loaded: {error}")
            history_df = pd.DataFrame()
        if history_df.empty:
            st.info("No grounded assistant queries have been recorded for this incident.")
        else:
            st.dataframe(history_df, width="stretch", hide_index=True)

    with audit_tab:
        audit_df = pd.DataFrame(details["audit"])
        if audit_df.empty:
            st.info("No case audit records are available.")
        else:
            if "details" in audit_df.columns:
                audit_df["details"] = audit_df["details"].apply(
                    lambda value: json.dumps(value, sort_keys=True)
                )
            st.dataframe(audit_df, width="stretch", hide_index=True)
