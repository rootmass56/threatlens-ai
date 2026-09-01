from pathlib import Path

import pytest
import yaml

from core.pipeline import analyze_linux_auth_log
from core.rules.engine import _match_expression
from core.rules.fixtures import RuleFixtureRunner
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.validation import RuleValidator

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def test_rule_catalog_is_valid_and_contains_governed_detection_catalog():
    report = RuleLoader().validation_report()
    assert report.valid, [issue.message for issue in report.issues]
    assert len(report.rules) == 46
    required = {
        "multiple_failed_logins",
        "invalid_user_enumeration",
        "successful_login_after_failures",
        "suspicious_sudo_command",
        "windows_failed_logons",
        "windows_encoded_powershell",
        "windows_audit_log_cleared",
        "windows_account_to_task_sequence",
        "sysmon_lsass_access",
        "sysmon_remote_thread_creation",
        "sysmon_office_spawns_shell",
        "suricata_c2_alert",
        "suricata_dns_tunneling",
        "suricata_smb_exploit_alert",
        "zeek_port_scan",
        "zeek_nxdomain_burst",
        "zeek_executable_download",
    }
    names = {rule.detection_name for rule in report.rules}
    assert required <= names
    assert all(rule.primary_attack.technique_id.startswith("T") for rule in report.rules)
    assert all(rule.lifecycle.owner for rule in report.rules)
    assert all(rule.lifecycle.reviewers for rule in report.rules)
    assert all(rule.lifecycle.changelog for rule in report.rules)


def test_all_rule_positive_negative_and_boundary_fixtures():
    loader = RuleLoader()
    rules = loader.load(enabled_only=False)
    for rule in rules:
        manifest_path = DEFAULT_RULE_DIRECTORY / rule.fixtures.manifest
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig"))
        assert manifest["rule"] == rule.detection_name
        assert len(manifest["cases"]) >= 3
        assert {case["case_type"] for case in manifest["cases"]} >= {
            "positive",
            "negative",
            "boundary",
        }

    report = RuleFixtureRunner().run()
    assert report.passed, [item for item in report.results if not item.passed]
    assert report.passed_count == 138


def _write_minimal_fixture_manifest(
    directory: Path,
    fixture_name: str,
    rule_name: str | None = None,
) -> str:
    manifest_rule_name = rule_name or fixture_name
    fixture_dir = directory / "fixtures" / fixture_name
    fixture_dir.mkdir(parents=True)
    for name in ("positive", "negative", "boundary"):
        (fixture_dir / f"{name}.log").write_text(
            "Aug  5 10:00:00 host sshd[1]: Accepted password for test from 192.0.2.1\n",
            encoding="utf-8",
        )
    manifest = {
        "rule": manifest_rule_name,
        "cases": [
            {
                "name": "positive",
                "case_type": "positive",
                "file": "positive.log",
                "expected_alerts": 1,
            },
            {
                "name": "negative",
                "case_type": "negative",
                "file": "negative.log",
                "expected_alerts": 0,
            },
            {
                "name": "boundary",
                "case_type": "boundary",
                "file": "boundary.log",
                "expected_alerts": 0,
            },
        ],
    }
    (fixture_dir / "manifest.yml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    return f"fixtures/{fixture_name}/manifest.yml"


def test_duplicate_rule_ids_are_rejected(tmp_path):
    source = DEFAULT_RULE_DIRECTORY / "linux" / "multiple_failed_logins.yml"
    payload = yaml.safe_load(source.read_text(encoding="utf-8-sig"))
    payload["fixtures"]["manifest"] = _write_minimal_fixture_manifest(
        tmp_path,
        "first",
        "multiple_failed_logins",
    )
    (tmp_path / "first.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    payload["detection_name"] = "duplicate_detection_name"
    payload["fixtures"]["manifest"] = _write_minimal_fixture_manifest(
        tmp_path,
        "duplicate_detection_name",
    )
    (tmp_path / "second.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    report = RuleValidator().validate_directory(tmp_path)
    assert not report.valid
    assert any("Duplicate rule ID" in issue.message for issue in report.issues)


def test_invalid_operator_is_rejected(tmp_path):
    source = DEFAULT_RULE_DIRECTORY / "linux" / "suspicious_sudo_command.yml"
    payload = yaml.safe_load(source.read_text(encoding="utf-8-sig"))
    payload["fixtures"]["manifest"] = _write_minimal_fixture_manifest(tmp_path, "invalid")
    selection = payload["detection"]["selections"]["sensitive_resource"]
    selection["command_line|unsupported_operator"] = selection.pop("command_line|contains")
    path = tmp_path / "invalid.yml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    report = RuleValidator().validate_directory(tmp_path)
    assert not report.valid
    assert any("Unsupported operator" in issue.message for issue in report.issues)


@pytest.mark.parametrize(
    ("actual", "operator", "expected", "result"),
    [
        ("PowerShell.exe", "equals", "powershell.exe", True),
        ("cat /etc/shadow", "contains", "/etc/shadow", True),
        ("abc", "not_contains", "xyz", True),
        ("prefix-value", "starts_with", "prefix", True),
        ("archive.zip", "ends_with", ".zip", True),
        ("user123", "regex", r"user\d+", True),
        (10, "greater_than", 5, True),
        (3, "less_than", 5, True),
        (None, "exists", False, True),
    ],
)
def test_generic_operator_semantics(actual, operator, expected, result):
    assert _match_expression(actual, operator, expected) is result


def test_yaml_pipeline_retains_validated_sample_output():
    pipeline = analyze_linux_auth_log(SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig"))
    assert pipeline.event_count == 9
    assert pipeline.alert_count == 4
    assert pipeline.incident_count == 1
    assert pipeline.quarantined_count == 0
    assert set(pipeline.alerts_df["rule_status"]) == {"stable"}
    assert pipeline.alerts_df["rule_id"].str.len().eq(36).all()
    assert pipeline.alerts_df["rule_owner"].eq("ThreatLens AI Detection Engineering").all()
    sudo = pipeline.alerts_df[
        pipeline.alerts_df["detection_name"] == "suspicious_sudo_command"
    ].iloc[0]
    assert sudo["mitre_technique_id"] == "T1548.003"
    assert sudo["playbook"] == "linux_privilege_abuse"
