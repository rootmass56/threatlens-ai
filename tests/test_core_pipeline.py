from pathlib import Path

from core.correlation_engine import correlate_alerts
from core.detection_engine import detect_alerts
from core.log_parser import parse_linux_auth_log
from core.timeline_builder import build_timeline

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def load_sample_log() -> str:
    return SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig")


def test_sample_log_file_exists():
    assert SAMPLE_LOG_PATH.exists()


def test_linux_parser_parses_all_events():
    events = parse_linux_auth_log(load_sample_log())
    assert len(events) == 9
    assert "unparsed" not in set(events["event_type"])
    assert len(events[events["event_type"] == "failed_login_invalid_user"]) == 5
    assert len(events[events["event_type"] == "successful_login"]) == 2
    sudo_events = events[events["event_type"] == "sudo_command"]
    assert len(sudo_events) == 1
    assert "/etc/shadow" in sudo_events.iloc[0]["normalized_message"]


def test_detection_engine_generates_expected_alerts_and_evidence():
    events = parse_linux_auth_log(load_sample_log())
    alerts = detect_alerts(events)
    assert len(alerts) == 4
    assert {
        "multiple_failed_logins",
        "invalid_user_enumeration",
        "successful_login_after_failures",
        "suspicious_sudo_command",
    } == set(alerts["detection_name"])
    brute_force = alerts[alerts["detection_name"] == "multiple_failed_logins"].iloc[0]
    assert len(brute_force["supporting_event_ids"]) == 5
    sudo_alert = alerts[alerts["detection_name"] == "suspicious_sudo_command"].iloc[0]
    assert sudo_alert["mitre_technique_id"] == "T1548.003"
    assert isinstance(sudo_alert["risk_factors"], dict)


def test_entity_and_time_correlation_builds_attack_storyline():
    events = parse_linux_auth_log(load_sample_log())
    alerts = detect_alerts(events)
    incidents = correlate_alerts(alerts)
    timeline = build_timeline(events, alerts)
    assert len(incidents) == 1
    assert not timeline.empty
    incident = incidents.iloc[0]
    assert incident["incident_name"] == "Account Compromise with Privilege Escalation"
    assert incident["alert_count"] == 4
    assert incident["alert_ids"] == [1, 2, 3, 4]


def test_account_compromise_risk_is_critical():
    events = parse_linux_auth_log(load_sample_log())
    alerts = detect_alerts(events)
    compromise = alerts[alerts["detection_name"] == "successful_login_after_failures"]
    assert not compromise.empty
    assert compromise.iloc[0]["severity"] == "Critical"
    assert int(compromise.iloc[0]["risk_score"]) == 100
