from pathlib import Path

from core.connectors import build_default_connector_registry

SAMPLES = {
    "auth_sample.log": "linux_auth",
    "windows_security_sample.jsonl": "windows_security",
    "sysmon_sample.jsonl": "windows_sysmon",
    "suricata_eve_sample.jsonl": "suricata_eve",
    "zeek_conn_sample.log": "zeek",
    "zeek_dns_sample.log": "zeek",
}


def main() -> None:
    sample_dir = Path("data/sample_logs")
    registry = build_default_connector_registry()
    for filename, expected in SAMPLES.items():
        path = sample_dir / filename
        detection = registry.detect(path.read_bytes(), filename=path.name)
        result = detection.connector.parse(path.read_bytes(), filename=path.name)
        actual = detection.connector.metadata.connector_id
        assert actual == expected, f"{filename}: expected {expected}, got {actual}"
        assert result.statistics.quarantined_records == 0
        print(
            f"{filename}: {actual}, confidence={detection.validation.confidence:.3f}, "
            f"events={len(result.events)}, success={result.statistics.parse_success_rate:.1%}"
        )


if __name__ == "__main__":
    main()
