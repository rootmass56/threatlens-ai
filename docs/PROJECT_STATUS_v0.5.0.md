# ThreatLens AI v0.5.0 Project Status

## Release objective

v0.5.0 extends the stable v0.4.1 common-schema and YAML-rule foundation into a heterogeneous telemetry platform. It adds validated connectors for Windows Security, Sysmon, Suricata EVE and Zeek while preserving Linux authentication support.

## Completed capabilities

- Five registered connectors: Linux auth.log, Windows Security, Sysmon, Suricata EVE and Zeek.
- Automatic source detection with confidence and validation evidence.
- JSON, JSONL/NDJSON, CSV and Zeek native TSV ingestion.
- Multi-file batch analysis with one source manifest and global event identifiers.
- Cross-source deterministic rule execution, correlation, timeline generation and atomic persistence.
- Twelve validated YAML rules with thirty-six positive, negative and boundary fixtures.
- Connector health and rule-coverage dashboard.
- Quarantine handling for malformed structured records and schema validation failures.
- Linux v0.4 regression output preserved at 9 events, 4 alerts, 1 incident and 0 quarantined records.
- Multi-source demonstration output: 22 events, 8 alerts, 2 incidents and 0 quarantined records.

## Honest maturity statement

This release provides multi-source ingestion and representative detections. It does not yet claim production-scale collection, complete source coverage, full ATT&CK detection coverage, advanced graph correlation, API/RBAC, RAG, PostgreSQL concurrency or containerized deployment.
