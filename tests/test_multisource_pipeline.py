from pathlib import Path

from core.pipeline import SourceInput, analyze_sources

SAMPLE_DIR = Path("data/sample_logs")


def _source(filename: str) -> SourceInput:
    path = SAMPLE_DIR / filename
    return SourceInput(raw_content=path.read_bytes(), filename=path.name)


def test_multi_source_pipeline_combines_events_and_connectors():
    result = analyze_sources(
        [
            _source("windows_security_sample.jsonl"),
            _source("sysmon_sample.jsonl"),
            _source("suricata_eve_sample.jsonl"),
            _source("zeek_conn_sample.log"),
            _source("zeek_dns_sample.log"),
        ]
    )
    assert result.event_count == 22
    assert result.quarantined_count == 0
    assert set(result.connector_ids) == {
        "windows_security",
        "windows_sysmon",
        "suricata_eve",
        "zeek",
    }
    assert result.connector_id == "multi_source"
    assert len(result.source_manifest) == 5
    assert result.events_df["event_id"].tolist() == list(range(1, 23))
    assert result.alert_count == 7
    assert result.incident_count >= 1
    assert result.parse_success_rate == 1.0


def test_multi_source_statistics_are_aggregated():
    result = analyze_sources(
        [_source("windows_security_sample.jsonl"), _source("sysmon_sample.jsonl")]
    )
    statistics = result.combined_parser_statistics()
    assert statistics["source_count"] == 2
    assert statistics["total_records"] == 9
    assert statistics["parsed_records"] == 9
    assert statistics["quarantined_records"] == 0
    assert statistics["parse_success_rate"] == 1.0
