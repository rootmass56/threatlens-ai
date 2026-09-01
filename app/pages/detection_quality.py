import pandas as pd
import plotly.express as px
import streamlit as st

from app.api_client import ThreatLensApiClient


def _mapping_frame(mapping: dict[str, int], key_name: str) -> pd.DataFrame:
    return pd.DataFrame(
        [{key_name: key, "rules": value} for key, value in mapping.items()]
    ).sort_values("rules", ascending=False)


def render_detection_quality(
    application_service: ThreatLensApiClient,
) -> None:
    """Render governed detection-catalog quality and coverage evidence."""

    st.header("Detection Engineering Quality")
    summary = application_service.get_rule_quality_summary()
    st.caption(
        "Governance, fixture coverage, review state, tuning controls and telemetry distribution "
        f"for governed detection catalogue v{summary['catalog_version']}."
    )

    records = application_service.get_rule_quality_records()
    profiles = application_service.get_rule_profiles()

    row_one = st.columns(5)
    row_one[0].metric("Rules", summary["total_rules"])
    row_one[1].metric("Fixture Cases", summary["fixture_cases"])
    row_one[2].metric(
        "Lifecycle Complete",
        f"{summary['lifecycle_completeness_percent']:.1f}%",
    )
    row_one[3].metric(
        "Fixture Complete",
        f"{summary['fixture_completeness_percent']:.1f}%",
    )
    row_one[4].metric(
        "Governance Score",
        f"{summary['governance_score_percent']:.1f}%",
    )

    row_two = st.columns(5)
    row_two[0].metric("Stable", summary["stable_rules"])
    row_two[1].metric("Test", summary["test_rules"])
    row_two[2].metric("Allowlists", summary["rules_with_allowlists"])
    row_two[3].metric("Suppression", summary["rules_with_suppression"])
    row_two[4].metric("Overdue Reviews", summary["overdue_reviews"])

    if summary["overdue_reviews"]:
        st.error("One or more detection rules require governance review.")
    else:
        st.success("All detection-rule reviews are current or due within the accepted window.")

    chart_columns = st.columns(3)
    with chart_columns[0]:
        st.subheader("Rules by Telemetry")
        frame = _mapping_frame(summary["rules_by_dataset"], "dataset")
        st.plotly_chart(
            px.bar(frame, x="dataset", y="rules", text_auto=True),
            width="stretch",
        )
    with chart_columns[1]:
        st.subheader("Rules by Severity")
        frame = _mapping_frame(summary["rules_by_severity"], "severity")
        st.plotly_chart(
            px.bar(frame, x="severity", y="rules", text_auto=True),
            width="stretch",
        )
    with chart_columns[2]:
        st.subheader("Rules by ATT&CK Tactic")
        frame = _mapping_frame(summary["rules_by_tactic"], "tactic")
        st.plotly_chart(
            px.bar(frame, x="tactic", y="rules", text_auto=True),
            width="stretch",
        )

    with st.expander("Environment-Specific Rule Profiles"):
        st.caption(
            "Profiles change approved thresholds or rule enablement without editing the governed "
            "source YAML. Set THREATLENS_RULE_PROFILE to default, lab or production before startup."
        )
        st.dataframe(profiles, width="stretch", hide_index=True)

    st.subheader("Per-Rule Governance Evidence")
    if records.empty:
        st.info("No rule-quality records are available.")
        return

    filters = st.columns(4)
    owner = filters[0].multiselect(
        "Owner",
        sorted(records["owner"].dropna().unique()),
        default=sorted(records["owner"].dropna().unique()),
    )
    review_state = filters[1].multiselect(
        "Review state",
        sorted(records["review_state"].dropna().unique()),
        default=sorted(records["review_state"].dropna().unique()),
    )
    status = filters[2].multiselect(
        "Rule status",
        sorted(records["status"].dropna().unique()),
        default=sorted(records["status"].dropna().unique()),
    )
    minimum_score = filters[3].slider(
        "Minimum governance score",
        min_value=0,
        max_value=100,
        value=0,
    )

    filtered = records[
        records["owner"].isin(owner)
        & records["review_state"].isin(review_state)
        & records["status"].isin(status)
        & (records["governance_score"] >= minimum_score)
    ].copy()

    display_columns = [
        "detection_name",
        "status",
        "owner",
        "version",
        "last_reviewed",
        "next_review_due",
        "review_state",
        "fixture_count",
        "attack_mapping_count",
        "false_positive_count",
        "allowlist_count",
        "suppression_enabled",
        "governance_score",
    ]
    st.dataframe(
        filtered[display_columns],
        width="stretch",
        hide_index=True,
    )

    st.download_button(
        "Download Detection Quality CSV",
        filtered[display_columns].to_csv(index=False).encode("utf-8"),
        file_name=f"threatlens_rules_v{summary['catalog_version']}_quality.csv",
        mime="text/csv",
    )
