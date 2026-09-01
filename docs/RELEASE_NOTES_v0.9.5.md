# ThreatLens AI v0.9.5 Release Notes

v0.9.5 is the final deterministic manual-UAT remediation candidate before grounded RAG work. The immutable v0.9.4 baseline passed its automated release gates, while end-to-end browser use exposed additional audit semantics, report completeness, API-contract and role-aware UI issues. This release closes those findings without changing the database schema or deterministic correlation model.

## Closed findings

- True no-op case workflow requests no longer update `updated_at` or write misleading `incident.workflow_updated` audit records.
- Incident PDF reports now include investigation notes and registered evidence metadata, including source reference, SHA-256, registrant and creation time where available.
- Incident evidence timelines are built only from events/alerts linked to each correlated incident; session events not linked to an incident are explicitly separated as additional analysis activity.
- Obsolete per-rule `parameters.catalog_version: 0.6.0` metadata is removed from the 12 affected current rule files; the governed catalogue remains v0.7.0.
- The protected OpenAPI contract now declares incident PDF `200` responses as `application/pdf` binary content.
- The built-in multi-source demonstration preserves a non-empty analyst-supplied analysis name.
- Case Details derives write affordances from authenticated permissions/object assignment. Viewer workflow, note and evidence views are read-only while the API continues to enforce authorization independently.
- Selecting a case synchronizes its persisted analysis context so the main workspace, current analysis and sidebar active-case state agree.
- Streamlit telemetry/evidence upload widgets use the authoritative API per-file limit, with exact byte validation before evidence hashing/submission.
- Governed rule source provenance shown through API/UI is repository-relative rather than an absolute host filesystem path.
- Hard browser refresh reauthentication is documented as deliberate server-session-only token handling; v0.9.5 does not weaken security by persisting JWTs into browser localStorage or JavaScript-readable cookies.

## Final browser-UAT polish

- True no-op workflow submissions now explicitly report that the case was not modified and no audit record was created.
- The incident-report recommendation heading and actions are kept together so a final response action is not orphaned on an otherwise nearly empty page.
- Telemetry and evidence upload screens explain that Streamlit may display a rounded-up decimal-MB transport cap while ThreatLens continues to enforce the exact MiB/byte API boundary before submission.

## Scope boundary

There is no Alembic migration; head remains `c31f9a7d4e20`. Existing persisted evidence gains registrant display/report attribution from its historical audit record without data rewriting.

The validated deterministic analytics baselines remain Linux 9/4/1/0 and five-source 22/8/2/0. Advanced five-source correlation remains 8 input alerts, 7 representative alerts, 1 deduplicated alert, 10 entities, 15 relationships, 2 incidents and a deterministic 30-node/62-edge graph. The API remains 39 paths / 40 operations.
