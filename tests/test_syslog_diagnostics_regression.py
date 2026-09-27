from core.connectors import build_default_connector_registry


def test_syslog_diagnostics_reject_windows_messages_and_accept_collector_envelopes() -> None:
    registry = build_default_connector_registry()
    with open("data/sample_logs/windows_security_sample.jsonl", "rb") as source_file:
        windows_source = source_file.read()
    diagnostics = {
        item.connector.metadata.connector_id: item.validation
        for item in registry.diagnostics(windows_source, filename="windows_security_sample.jsonl")
    }
    assert diagnostics["windows_security"].valid is True
    assert diagnostics["windows_security"].confidence == 1.0
    assert diagnostics["syslog_rfc"].valid is False
    assert diagnostics["syslog_rfc"].confidence == 0.0

    collector_envelope = (
        b'{"client_event_id":"syslog-test-1","message":"custom application notice",'
        b'"source_ip":"192.0.2.10","received_at":"2026-09-20T00:00:00Z","transport":"udp"}'
    )
    syslog = registry.get("syslog_rfc")
    validation = syslog.validate_source(collector_envelope, filename="syslog-envelope.json")
    assert validation.valid is True
    assert validation.confidence == 1.0
    parsed = syslog.parse(collector_envelope, filename="syslog-envelope.json")
    assert parsed.statistics.parsed_records == 1
    assert parsed.events[0].source_dataset == "syslog_rfc"
