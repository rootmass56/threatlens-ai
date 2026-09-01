# ThreatLens AI v0.6.0 Release Notes

## Summary

v0.6.0 transforms the representative v0.5 rule set into a governed detection-engineering catalogue with 42 rules, 126 fixtures, lifecycle controls, tuning profiles, allowlists, suppression and quality analytics.

## Major additions

- Expanded Windows Security detections for audit, account, privilege, persistence and LOLBin behaviors.
- Expanded Sysmon detections for process injection, credential access, registry persistence, user-writable execution, network activity and file operations.
- Expanded Suricata detections for DNS, HTTP, TLS, SSH, SMB exploitation and file transfer.
- Expanded Zeek detections for DNS anomalies, executable download, TLS SNI and failed connections.
- Added an ordered Windows account-to-task persistence sequence.
- Added environment-specific tuning profiles.
- Added Detection Quality dashboard.
- Added deterministic allowlist and suppression metrics.

## Compatibility

- Python 3.11.
- Existing v0.5 database remains compatible.
- Linux and multi-source regression outputs remain unchanged.
