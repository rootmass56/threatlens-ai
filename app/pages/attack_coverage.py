from __future__ import annotations

import plotly.express as px
import streamlit as st

from app.api_client import ThreatLensApiClient


def _render_sync_panel(application_service: ThreatLensApiClient) -> None:
    with st.expander("ATT&CK synchronization controls"):
        st.caption(
            "Synchronization downloads the pinned official Enterprise, Mobile and ICS ATT&CK "
            "v19.1 STIX 2.1 bundles, validates exact catalog counts, stores every object and "
            "relationship, and rebuilds Enterprise rule mappings transactionally."
        )
        force = st.checkbox(
            "Force redownload of the pinned v19.1 bundle",
            value=False,
            help="Normally the validated local bundle is reused.",
        )
        if st.button("Synchronize All ATT&CK v19.1 Domains", type="primary"):
            actor = st.session_state.get("analyst_identity") or "streamlit"
            with st.spinner("Synchronizing complete official ATT&CK v19.1 catalogs..."):
                try:
                    result = application_service.synchronize_attack_catalog(
                        actor=actor,
                        force_download=force,
                    )
                except Exception as error:  # pragma: no cover - UI boundary
                    st.exception(error)
                else:
                    domains = result["domains"]
                    st.success(
                        "Synchronized all official ATT&CK v19.1 domains: "
                        + ", ".join(
                            f"{item['domain']} ({item['technique_count']} techniques, "
                            f"{item['subtechnique_count']} sub-techniques)"
                            for item in domains
                        )
                    )
                    st.rerun()


def render_attack_coverage(
    application_service: ThreatLensApiClient,
) -> None:
    """Render full-catalog awareness separately from evidence-backed detection coverage."""

    st.header("MITRE ATT&CK Catalog and Detection Coverage")
    st.caption(
        "Complete official Enterprise, Mobile and ICS ATT&CK catalog awareness, versioned "
        "Enterprise rule mappings, telemetry-aware gaps and Navigator export."
    )

    st.info(
        "Catalog awareness and detection coverage are different. ThreatLens stores and exposes "
        "the complete pinned ATT&CK catalogs, but marks a technique as covered only "
        "when a validated rule and available telemetry support that claim."
    )

    statuses = application_service.get_attack_catalog_statuses()
    if statuses.empty:
        st.warning(
            "No synchronized ATT&CK catalog is active. Run setup.ps1 or use the synchronization "
            "control below."
        )
        _render_sync_panel(application_service)
        return

    total_metrics = st.columns(5)
    total_metrics[0].metric("Official Domains", len(statuses))
    total_metrics[1].metric("All-Domain Tactics", int(statuses["tactic_count"].sum()))
    total_metrics[2].metric(
        "All-Domain Techniques",
        int(statuses["technique_count"].sum()),
    )
    total_metrics[3].metric(
        "All-Domain Sub-techniques",
        int(statuses["subtechnique_count"].sum()),
    )
    total_metrics[4].metric("Catalog Awareness", "100.0%")

    domain_labels = dict(zip(statuses["domain"], statuses["display_name"], strict=True))
    selected_domain = st.selectbox(
        "ATT&CK domain",
        options=list(domain_labels),
        format_func=lambda value: domain_labels[value],
    )
    status = application_service.get_attack_catalog_status(selected_domain)
    if status is None:
        st.error("The selected ATT&CK domain is not synchronized.")
        return

    first = st.columns(6)
    first[0].metric("ATT&CK Release", f"v{status['version']}")
    first[1].metric("Domain Tactics", status["tactic_count"])
    first[2].metric("Techniques", status["technique_count"])
    first[3].metric("Sub-techniques", status["subtechnique_count"])
    first[4].metric("Catalog Awareness", "100.0%")
    first[5].metric("STIX Relationships", status["relationship_count"])

    second = st.columns(5)
    second[0].metric("Rule Mappings", status["mapping_count"])
    second[1].metric("Valid Mappings", status["valid_mapping_count"])
    second[2].metric("Invalid Mappings", status["invalid_mapping_count"])
    second[3].metric("Mapped ATT&CK IDs", status["unique_mapped_attack_ids"])
    second[4].metric("Rule Coverage", f"{status['rule_coverage_percent']:.2f}%")

    expected_counts = {
        "enterprise-attack": (15, 222, 475),
        "mobile-attack": (12, 77, 47),
        "ics-attack": (12, 79, 18),
    }
    expected = expected_counts[selected_domain]
    if (
        status["tactic_count"],
        status["technique_count"],
        status["subtechnique_count"],
    ) == expected:
        st.success(
            f"Complete pinned {status['display_name']} v19.1 catalog is active: "
            f"all {expected[0]} tactics, {expected[1]} techniques and "
            f"{expected[2]} sub-techniques are queryable."
        )
    else:
        st.error("The active catalog does not match the pinned v19.1 acceptance counts.")

    source_columns = st.columns(3)
    source_columns[0].write(f"**Collection ID:** `{status['collection_id']}`")
    source_columns[1].write(f"**Source modified:** `{status['source_modified']}`")
    source_columns[2].write(f"**Synchronized:** `{status['synced_at']}`")
    st.code(status["content_sha256"], language=None)
    st.caption("SHA-256 fingerprint of the synchronized official STIX bundle")

    techniques = application_service.get_attack_techniques(selected_domain)
    mappings = (
        application_service.get_attack_rule_mappings()
        if selected_domain == "enterprise-attack"
        else application_service.get_attack_rule_mappings().iloc[0:0]
    )
    object_types = application_service.get_attack_object_types(selected_domain)

    catalog_tab, mapping_tab, gap_tab, data_tab = st.tabs(
        [
            "Complete Technique Catalog",
            "Evidence-Backed Rule Mappings",
            "Coverage Gaps",
            "STIX Data Inventory",
        ]
    )

    with catalog_tab:
        st.subheader(f"All {status['display_name']} Techniques and Sub-techniques")
        if techniques.empty:
            st.info("No technique records are available.")
        else:
            filters = st.columns(4)
            object_types_selected = filters[0].multiselect(
                "Type",
                sorted(techniques["type"].unique()),
                default=sorted(techniques["type"].unique()),
            )
            coverage_states = filters[1].multiselect(
                "Coverage state",
                sorted(techniques["coverage_state"].unique()),
                default=sorted(techniques["coverage_state"].unique()),
            )
            platform_query = filters[2].text_input("Platform contains")
            tactic_query = filters[3].text_input("Tactic contains")
            search_query = st.text_input(
                "Search ATT&CK ID or name",
                placeholder="Example: T1059.001 or PowerShell",
            )

            filtered = techniques[
                techniques["type"].isin(object_types_selected)
                & techniques["coverage_state"].isin(coverage_states)
            ].copy()
            if platform_query:
                filtered = filtered[
                    filtered["platforms"].str.contains(
                        platform_query,
                        case=False,
                        na=False,
                    )
                ]
            if tactic_query:
                filtered = filtered[
                    filtered["tactics"].str.contains(tactic_query, case=False, na=False)
                ]
            if search_query:
                filtered = filtered[
                    filtered["attack_id"].str.contains(
                        search_query,
                        case=False,
                        na=False,
                    )
                    | filtered["name"].str.contains(
                        search_query,
                        case=False,
                        na=False,
                    )
                ]

            st.caption(f"Showing {len(filtered)} of {len(techniques)} active ATT&CK records.")
            st.dataframe(
                filtered[
                    [
                        "attack_id",
                        "name",
                        "type",
                        "parent_attack_id",
                        "tactics",
                        "platforms",
                        "coverage_state",
                        "modified",
                        "external_url",
                    ]
                ],
                width="stretch",
                hide_index=True,
                column_config={
                    "external_url": st.column_config.LinkColumn("Official ATT&CK page"),
                },
            )
            st.download_button(
                "Download Complete ATT&CK Technique Catalog CSV",
                techniques.to_csv(index=False).encode("utf-8"),
                file_name=f"threatlens_{selected_domain}_v19.1_catalog.csv",
                mime="text/csv",
            )

    with mapping_tab:
        st.subheader("Versioned Rule-to-Technique Mapping Evidence")
        if mappings.empty:
            if selected_domain == "enterprise-attack":
                st.info("No rule mappings are available.")
            else:
                st.info(
                    "This domain is fully synchronized for catalog awareness. Current ThreatLens "
                    "telemetry and governed detections target Enterprise ATT&CK, so Mobile and "
                    "ICS objects are intentionally not claimed as detected."
                )
        else:
            valid_count = int(mappings["valid"].sum())
            st.write(
                f"**{valid_count}/{len(mappings)} mappings are valid against the pinned "
                "official catalog.**"
            )
            if not mappings["valid"].all():
                st.error("One or more rule mappings require correction before release.")
            if not mappings["tactic_consistent"].all():
                st.warning(
                    "Some technique IDs are valid but their declared tactic labels require "
                    "taxonomy review."
                )

            dataset_counts = (
                mappings[mappings["valid"]]
                .groupby("dataset", dropna=False)["attack_id"]
                .nunique()
                .reset_index(name="mapped_attack_ids")
            )
            st.plotly_chart(
                px.bar(
                    dataset_counts,
                    x="dataset",
                    y="mapped_attack_ids",
                    text_auto=True,
                    title="Unique Evidence-Backed ATT&CK IDs by Telemetry Dataset",
                ),
                width="stretch",
            )
            st.dataframe(
                mappings,
                width="stretch",
                hide_index=True,
            )
            st.download_button(
                "Download Rule Mapping Evidence CSV",
                mappings.to_csv(index=False).encode("utf-8"),
                file_name="threatlens_attack_v19.1_rule_mappings.csv",
                mime="text/csv",
            )

            try:
                navigator_payload = application_service.get_attack_navigator_json()
            except Exception as error:  # pragma: no cover - UI boundary
                st.warning(f"Navigator export is currently unavailable: {error}")
            else:
                st.download_button(
                    "Download ATT&CK Navigator Layer JSON",
                    navigator_payload,
                    file_name="threatlens_attack_v19.1_detection_coverage.json",
                    mime="application/json",
                )

    with gap_tab:
        st.subheader("Explicit Telemetry and Detection Gaps")
        st.caption(
            "Unmapped items remain fully queryable catalog records. They are not called "
            "detected or covered until a validated rule and appropriate telemetry exist."
        )
        gaps = techniques[~techniques["mapped_by_rule"]].copy()
        mapped = techniques[techniques["mapped_by_rule"]].copy()
        gap_columns = st.columns(3)
        gap_columns[0].metric("Catalog ATT&CK IDs", len(techniques))
        gap_columns[1].metric("Evidence-Backed IDs", len(mapped))
        gap_columns[2].metric("Explicit Gaps", len(gaps))
        st.dataframe(
            gaps[
                [
                    "attack_id",
                    "name",
                    "type",
                    "tactics",
                    "platforms",
                    "coverage_state",
                    "external_url",
                ]
            ],
            width="stretch",
            hide_index=True,
            column_config={
                "external_url": st.column_config.LinkColumn("Official ATT&CK page"),
            },
        )
        st.download_button(
            "Download ATT&CK Coverage Gaps CSV",
            gaps.to_csv(index=False).encode("utf-8"),
            file_name=f"threatlens_{selected_domain}_v19.1_coverage_gaps.csv",
            mime="text/csv",
        )

    with data_tab:
        st.subheader("Complete Persisted STIX Object Inventory")
        st.caption(
            "ThreatLens persists normalized indexes and the complete raw JSON payload for every "
            "non-relationship STIX object, plus every relationship object separately."
        )
        if object_types.empty:
            st.info("No STIX object inventory is available.")
        else:
            st.plotly_chart(
                px.bar(
                    object_types,
                    x="object_type",
                    y="active_objects",
                    text_auto=True,
                    title="Active ATT&CK Objects by STIX Type",
                ),
                width="stretch",
            )
            st.dataframe(object_types, width="stretch", hide_index=True)

    _render_sync_panel(application_service)
