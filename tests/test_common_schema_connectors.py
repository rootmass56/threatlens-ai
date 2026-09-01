from pathlib import Path

from core.connectors import LinuxAuthConnector, build_default_connector_registry
from core.schema import COMMON_EVENT_SCHEMA_VERSION, ParseStatus

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def test_linux_connector_auto_detection_and_common_schema():
    raw = SAMPLE_LOG_PATH.read_bytes()
    registry = build_default_connector_registry()
    detection = registry.detect(raw, filename=SAMPLE_LOG_PATH.name)
    assert detection.connector.metadata.connector_id == "linux_auth"
    assert detection.validation.valid
    assert detection.validation.confidence >= 0.90

    result = registry.parse(raw, filename=SAMPLE_LOG_PATH.name)
    assert result.statistics.schema_version == COMMON_EVENT_SCHEMA_VERSION
    assert result.statistics.total_records == 9
    assert result.statistics.parsed_records == 9
    assert result.statistics.quarantined_records == 0
    assert result.statistics.parse_success_rate == 1.0
    assert all(event.schema_version == COMMON_EVENT_SCHEMA_VERSION for event in result.events)
    assert all(event.timestamp and event.timestamp.tzinfo for event in result.events)


def test_common_event_dataframe_contains_cross_source_fields():
    result = LinuxAuthConnector().parse(SAMPLE_LOG_PATH.read_bytes())
    frame = result.to_dataframe()
    required = {
        "schema_version",
        "event_uuid",
        "source_category",
        "source_product",
        "source_service",
        "source_dataset",
        "source_port",
        "destination_port",
        "command_line",
        "file_path",
        "parser_name",
        "parser_version",
        "parse_status",
        "data_quality",
        "attributes",
    }
    assert required.issubset(frame.columns)
    sudo = frame[frame["event_type"] == "sudo_command"].iloc[0]
    assert sudo["command_line"] == "/bin/cat /etc/shadow"
    assert sudo["file_path"] == "/etc/shadow"


def test_unrecognized_record_is_quarantined_not_silently_dropped():
    source = (
        "Jul 30 10:00:01 host sshd[1]: Accepted password for user "
        "from 192.0.2.1 port 22 ssh2\n"
        "this is not a syslog record\n"
    )
    result = LinuxAuthConnector().parse(source)
    assert len(result.events) == 1
    assert len(result.quarantined_records) == 1
    assert result.statistics.quarantined_records == 1
    assert result.quarantined_records[0].reason_code == "syslog_structure_mismatch"


def test_unknown_auth_message_is_partial_with_quality_reason():
    source = "Jul 30 10:00:01 host sshd[1]: Unsupported authentication message"
    result = LinuxAuthConnector().parse(source)
    assert len(result.events) == 1
    assert result.events[0].parse_status == ParseStatus.PARTIAL
    assert result.events[0].data_quality[-1].code == "unsupported_auth_message"


def test_invalid_ip_is_quarantined_by_schema_validation():
    source = (
        "Jul 30 10:00:01 host sshd[1]: Failed password for user from 999.999.999.999 port 22 ssh2"
    )
    result = LinuxAuthConnector().parse(source)
    assert not result.events
    assert result.statistics.quarantined_records == 1
    assert result.quarantined_records[0].reason_code == "common_schema_validation_failed"
