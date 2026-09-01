import pandas as pd
import yaml

from core.connectors import build_default_connector_registry
from core.rules import (
    RuleEngine,
    RuleLoader,
    RuleProfileLoader,
    RuleQualityAnalyzer,
)
from core.rules.loader import DEFAULT_RULE_DIRECTORY
from core.rules.validation import RuleValidator


def _rule(name: str):
    return next(
        rule for rule in RuleLoader().load(enabled_only=False) if rule.detection_name == name
    )


def _parse_fixture(rule_name: str, filename: str):
    rule = _rule(rule_name)
    path = DEFAULT_RULE_DIRECTORY / "fixtures" / rule_name / filename
    registry = build_default_connector_registry()
    return registry.parse(
        path.read_bytes(),
        filename=path.name,
        connector_id=rule.logsource.dataset or "linux_auth",
    ).to_dataframe()


def test_v06_catalog_quality_targets_are_met():
    analyzer = RuleQualityAnalyzer()
    summary = analyzer.summary()
    assert summary.total_rules == 46
    assert summary.enabled_rules == 46
    assert summary.fixture_cases == 138
    assert summary.rules_with_complete_fixtures == 46
    assert summary.lifecycle_completeness_percent == 100.0
    assert summary.fixture_completeness_percent == 100.0
    assert summary.governance_score_percent >= 95.0
    assert summary.overdue_reviews == 0
    assert summary.rules_with_allowlists >= 35
    assert summary.rules_with_suppression >= 35
    assert summary.rules_by_dataset == {
        "entra_id": 4,
        "linux_auth": 4,
        "suricata_eve": 8,
        "windows_security": 11,
        "windows_sysmon": 12,
        "zeek": 7,
    }


def test_allowlist_filters_matching_events_and_records_metrics():
    rule = _rule("windows_explicit_credential_logon")
    events = _parse_fixture(rule.detection_name, "boundary.jsonl")
    result = RuleEngine([rule]).evaluate_detailed(events)
    assert result.alerts.empty
    assert result.metrics.allowlisted_events == 1
    assert result.metrics.allowlisted_by_rule[rule.detection_name] == 1


def test_suppression_limits_repeated_alerts():
    rule = _rule("windows_audit_log_cleared")
    events = _parse_fixture(rule.detection_name, "positive.jsonl")
    duplicate = events.copy()
    duplicate["event_id"] = duplicate["event_id"] + 1
    duplicate["event_uuid"] = duplicate["event_uuid"].astype(str) + "-duplicate"
    combined = pd.concat([events, duplicate], ignore_index=True)
    result = RuleEngine([rule]).evaluate_detailed(combined)
    assert len(result.alerts) == 1
    assert result.metrics.suppressed_alerts == 1
    assert result.metrics.suppressed_by_rule[rule.detection_name] == 1


def test_cross_category_sequence_rule_detects_account_then_task():
    rule = _rule("windows_account_to_task_sequence")
    events = _parse_fixture(rule.detection_name, "positive.jsonl")
    result = RuleEngine([rule]).evaluate_detailed(events)
    assert len(result.alerts) == 1
    alert = result.alerts.iloc[0]
    assert alert["event_count"] == 2
    assert alert["mitre_technique_id"] == "T1053.005"


def test_rule_catalog_has_balanced_kinds_and_tactics():
    rules = RuleLoader().load(enabled_only=False)
    kinds = {rule.kind.value for rule in rules}
    tactics = {rule.primary_attack.tactic for rule in rules}
    assert kinds == {"event", "threshold", "sequence"}
    assert {
        "Credential Access",
        "Persistence",
        "Execution",
        "Defense Evasion",
        "Command and Control",
        "Discovery",
        "Lateral Movement",
    } <= tactics


def test_lifecycle_metadata_is_required(tmp_path):
    source = DEFAULT_RULE_DIRECTORY / "windows" / "windows_audit_log_cleared.yml"
    payload = yaml.safe_load(source.read_text(encoding="utf-8-sig"))
    payload.pop("lifecycle")
    path = tmp_path / "missing_lifecycle.yml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    report = RuleValidator().validate_directory(tmp_path)
    assert not report.valid
    assert any("lifecycle" in issue.message for issue in report.issues)


def test_quality_records_expose_review_and_governance_evidence():
    records = RuleQualityAnalyzer().records_as_dicts()
    assert len(records) == 46
    assert all(record["review_state"] in {"current", "due_soon"} for record in records)
    assert all(record["fixture_complete"] for record in records)
    assert all(record["lifecycle_complete"] for record in records)
    assert all(record["governance_score"] >= 87 for record in records)


def test_environment_profiles_are_valid_and_non_destructive():
    loader = RuleLoader()
    default_rules = loader.load(enabled_only=False, profile="default")
    lab_rules = loader.load(enabled_only=False, profile="lab")
    production_rules = loader.load(enabled_only=False, profile="production")
    assert len(default_rules) == len(lab_rules) == len(production_rules) == 46

    default_failed = next(
        rule for rule in default_rules if rule.detection_name == "windows_failed_logons"
    )
    lab_failed = next(rule for rule in lab_rules if rule.detection_name == "windows_failed_logons")
    assert default_failed.detection.threshold is not None
    assert lab_failed.detection.threshold is not None
    assert default_failed.detection.threshold.count == 5
    assert lab_failed.detection.threshold.count == 4

    production_enabled = {rule.detection_name for rule in production_rules if rule.enabled}
    assert "suricata_legacy_tls" not in production_enabled
    assert "windows_audit_log_cleared" in production_enabled

    profiles = RuleProfileLoader(loader.profile_path).available_profiles()
    assert {profile.name for profile in profiles} == {"default", "lab", "production"}
