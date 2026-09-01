# ThreatLens AI v0.5.0 Release Notes

## Release name

Multi-Source Security Telemetry Ingestion and Normalization

## Upgrade base

This source package is designed to upgrade the verified `v0.4.1` release. It intentionally excludes `.git`, `.venv`, runtime databases, caches and generated reports so the existing repository history and local evidence can be preserved.

## Main additions

- Windows Security, Sysmon, Suricata EVE and Zeek connectors.
- Multi-file analysis and per-source connector auto-detection.
- Twelve external YAML rules with thirty-six fixture cases.
- Connector diagnostics, source manifests and parser-quality summaries.
- Connector Health UI and multi-source demonstration dataset.

## Database compatibility

No new Alembic revision is required. v0.5 stores source manifests and aggregated parser statistics in existing JSON-capable metadata fields. The current migration head remains `e48a7c9d2f10`.

## Release limitations

The source adapters operate on authorized exported files and synthetic fixtures. Continuous agents, message queues, enterprise collectors and production-rate streaming are outside this milestone.
