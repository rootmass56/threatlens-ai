import json

import streamlit as st

from app.api_client import ThreatLensApiClient


def render_rule_catalog(application_service: ThreatLensApiClient) -> None:
    """Render validated external-rule metadata and fixture coverage."""

    st.header("Detection Rule Catalog")
    validation = application_service.get_rule_validation()
    rules_df = application_service.get_rule_catalog()
    fixtures_df = application_service.get_rule_fixture_results()

    metrics = st.columns(4)
    metrics[0].metric("Validated Rules", validation["rules"])
    metrics[1].metric("Enabled Rules", validation["enabled"])
    metrics[2].metric("Validation Issues", validation["issues"])
    metrics[3].metric(
        "Fixture Cases Passed",
        (
            f"{int(fixtures_df['passed'].sum())}/{len(fixtures_df)}"
            if not fixtures_df.empty
            else "0/0"
        ),
    )

    if validation["valid"]:
        st.success("All rule files and fixture references passed schema validation.")
    else:
        st.error("The rule catalog contains validation failures and cannot execute.")
        st.dataframe(validation["issues_detail"], width="stretch", hide_index=True)

    if not fixtures_df.empty:
        if fixtures_df["passed"].all():
            st.success("All positive, negative and boundary fixture cases passed.")
        else:
            st.error("One or more rule fixture cases failed.")
        with st.expander("Fixture execution evidence"):
            st.dataframe(fixtures_df, width="stretch", hide_index=True)

    if rules_df.empty:
        st.info("No rules are available.")
        return

    filters = st.columns(4)
    status_values = sorted(rules_df["status"].dropna().unique().tolist())
    kind_values = sorted(rules_df["kind"].dropna().unique().tolist())
    severity_values = sorted(rules_df["severity"].dropna().unique().tolist())
    technique_search = filters[3].text_input("ATT&CK technique contains")
    selected_status = filters[0].multiselect(
        "Status",
        options=status_values,
        default=status_values,
    )
    selected_kinds = filters[1].multiselect(
        "Rule kind",
        options=kind_values,
        default=kind_values,
    )
    selected_severities = filters[2].multiselect(
        "Severity",
        options=severity_values,
        default=severity_values,
    )

    filtered = rules_df[
        rules_df["status"].isin(selected_status)
        & rules_df["kind"].isin(selected_kinds)
        & rules_df["severity"].isin(selected_severities)
    ].copy()
    if technique_search:
        filtered = filtered[
            filtered["primary_technique_id"].str.contains(
                technique_search,
                case=False,
                regex=False,
            )
            | filtered["primary_technique"].str.contains(
                technique_search,
                case=False,
                regex=False,
            )
        ]

    display_columns = [
        "detection_name",
        "title",
        "version",
        "status",
        "enabled",
        "kind",
        "severity",
        "confidence",
        "dataset",
        "primary_technique_id",
        "primary_technique",
        "primary_tactic",
        "attack_mapping_count",
        "fixture_count",
        "owner",
        "last_reviewed",
        "allowlist_count",
        "suppression_enabled",
        "playbook",
    ]
    st.dataframe(filtered[display_columns], width="stretch", hide_index=True)

    if filtered.empty:
        return
    selected_rule_id = st.selectbox(
        "Inspect a validated rule",
        options=filtered["rule_id"].tolist(),
        format_func=lambda value: filtered.loc[
            filtered["rule_id"] == value,
            "title",
        ].iloc[0],
    )
    details = application_service.get_rule_details(selected_rule_id)
    if details:
        left, right = st.columns(2)
        with left:
            st.subheader("Rule Definition")
            st.json(
                {
                    key: details[key]
                    for key in (
                        "id",
                        "detection_name",
                        "version",
                        "status",
                        "enabled",
                        "kind",
                        "description",
                        "logsource",
                        "severity",
                        "confidence",
                        "risk",
                        "response",
                        "lifecycle",
                        "tuning",
                    )
                }
            )
        with right:
            st.subheader("Detection and ATT&CK")
            st.code(json.dumps(details["detection"], indent=2), language="json")
            st.json(details["attack"])
            st.caption(f"Source: {details.get('source_path')}")
