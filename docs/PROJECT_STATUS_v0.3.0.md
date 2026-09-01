# ThreatLens AI Project Status — v0.3.0

## Milestone decision

This release completes the persistent SOC case-management milestone. The platform is no longer limited to browser session memory: analyses, alerts, incidents, evidence relationships, notes and audit actions persist in the migration-controlled database and can be reloaded after restart.

## Completed

- Hardened Linux authentication parser
- Four validated prototype detections
- Explainable risk factor output
- Corrected sudo ATT&CK mapping to T1548.003
- Entity and 30-minute temporal correlation
- Explicit alert IDs and supporting event IDs
- `alert_events` database relationship and migration
- Atomic persistence and duplicate-ingestion control
- Persistent history and full analysis reload
- Incident queue and detailed case read model
- Controlled case-state transitions
- Analyst assignment and priority changes
- Investigation notes
- Evidence SHA-256 validation
- Audit-trail query and UI
- Modular Streamlit pages
- Pagination-safe PDF reporting
- 12 tests passing
- 87% coverage for the tested core/application/database scope

## Honest limitations

- Only the Linux auth connector is validated.
- Detection rules remain Python code rather than external YAML.
- ATT&CK support is still a four-rule prototype, not the full catalog service.
- Correlation is entity/time based but not yet cross-source graph correlation.
- SQLite is the development profile; PostgreSQL and Docker are not implemented.
- Authentication, RBAC, FastAPI and RAG are not implemented.
- Streamlit page behavior is manually verified; automated browser tests are still pending.

## Next milestone

v0.4 must implement the versioned common event schema and external Sigma-inspired YAML rule engine before adding more connectors or RAG.
