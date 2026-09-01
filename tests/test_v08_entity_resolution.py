import pandas as pd

from correlation.entities import EntityResolver, canonicalize


def test_entity_canonicalization_is_deterministic():
    assert canonicalize("ip", "192.168.001.010") == "192.168.001.010"
    assert canonicalize("hostname", "WorkStation-01.EXAMPLE.") == ("workstation-01.example")
    assert canonicalize("username", " LAB\\Alice ") == "lab\\alice"
    assert canonicalize("process", "C:/Windows/System32/PowerShell.EXE") == ("powershell.exe")


def test_resolver_combines_direct_and_supporting_event_entities():
    alerts = pd.DataFrame(
        [
            {
                "alert_id": 1,
                "event_id": 1,
                "supporting_event_ids": [1, 2],
                "timestamp": "2026-08-06T10:00:00Z",
                "source_ip": "10.0.0.5",
                "username": "LAB\\Alice",
                "hostname": "WORKSTATION-01",
                "source_dataset": "windows_security",
            }
        ]
    )
    events = pd.DataFrame(
        [
            {
                "event_id": 1,
                "timestamp": "2026-08-06T10:00:00Z",
                "source_dataset": "windows_security",
                "destination_ip": "198.51.100.10",
                "process_name": "powershell.exe",
                "attributes": {},
            },
            {
                "event_id": 2,
                "timestamp": "2026-08-06T10:00:10Z",
                "source_dataset": "windows_sysmon",
                "domain": "beacon.example.test",
                "attributes": {"sha256": "A" * 64},
            },
        ]
    )
    entities, mapping = EntityResolver().resolve(alerts, events)
    keys = set(entities["entity_key"])
    assert "ip:10.0.0.5" in keys
    assert "ip:198.51.100.10" in keys
    assert "username:lab\\alice" in keys
    assert "hostname:workstation-01" in keys
    assert "process:powershell.exe" in keys
    assert "domain:beacon.example.test" in keys
    assert f"hash:{'a' * 64}" in keys
    assert keys == mapping[1]
