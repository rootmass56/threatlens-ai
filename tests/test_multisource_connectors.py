from pathlib import Path

from core.connectors import build_default_connector_registry

SAMPLE_DIR = Path("data/sample_logs")


def test_default_registry_contains_current_governed_connectors():
    registry = build_default_connector_registry()
    assert registry.connector_ids() == [
        "entra_id",
        "linux_auth",
        "suricata_eve",
        "syslog_rfc",
        "windows_security",
        "windows_sysmon",
        "zeek",
    ]


def test_auto_detection_and_normalization_for_all_v05_sources():
    expected = {
        "auth_sample.log": ("linux_auth", 9),
        "windows_security_sample.jsonl": ("windows_security", 7),
        "sysmon_sample.jsonl": ("windows_sysmon", 2),
        "suricata_eve_sample.jsonl": ("suricata_eve", 2),
        "zeek_conn_sample.log": ("zeek", 10),
        "zeek_dns_sample.log": ("zeek", 1),
    }
    registry = build_default_connector_registry()
    for filename, (connector_id, event_count) in expected.items():
        path = SAMPLE_DIR / filename
        detected = registry.detect(path.read_bytes(), filename=path.name)
        assert detected.connector.metadata.connector_id == connector_id
        assert detected.validation.valid
        result = detected.connector.parse(path.read_bytes(), filename=path.name)
        assert len(result.events) == event_count
        assert result.statistics.quarantined_records == 0
        assert result.statistics.parse_success_rate == 1.0


def test_malformed_json_record_is_quarantined():
    registry = build_default_connector_registry()
    source = (
        b'{"EventID":4625,"TimeCreated":"2026-08-04T10:00:00Z",'
        b'"ProviderName":"Microsoft-Windows-Security-Auditing"}\n{bad json}\n'
    )
    result = registry.parse(
        source,
        filename="security.jsonl",
        connector_id="windows_security",
    )
    assert len(result.events) == 1
    assert len(result.quarantined_records) == 1
    assert result.quarantined_records[0].reason_code == "invalid_json_record"
