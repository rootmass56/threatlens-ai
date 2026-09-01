# Multi-Source Connector Architecture

Each connector implements `SecurityLogConnector` and returns a `ParserResult` containing validated `CommonEvent` objects, quarantined records, parser statistics and source metadata.

## Connector catalogue

| Connector | Formats | Representative telemetry |
|---|---|---|
| `linux_auth` | log, txt | OpenSSH, sudo, PAM and sessions |
| `windows_security` | JSON, JSONL, CSV | Event IDs 4624, 4625, 4688, 4719, 4720, 4728/4732 and 1102 |
| `windows_sysmon` | JSON, JSONL, CSV | Process, network, DNS, file, registry and process-access events |
| `suricata_eve` | EVE JSON/JSONL | Alert, DNS, HTTP, TLS, flow, SSH and fileinfo |
| `zeek` | Native TSV, JSON/JSONL | conn, dns, http and ssl/tls logs |

## Batch pipeline

`analyze_sources()` accepts heterogeneous `SourceInput` objects. Every file is detected or explicitly assigned, normalized independently, assigned global event IDs, evaluated against one rule catalogue, correlated and persisted as one analysis session. The source manifest records connector selection, confidence, parser success and quarantine counts.

## Safety and evidence controls

- Explicit validation evidence for auto-detection.
- No silent dropping of malformed records; failures enter quarantine.
- Original raw records are retained in normalized evidence.
- Per-source and aggregate parsing statistics are stored.
- Duplicate protection hashes a deterministic multi-source bundle.
