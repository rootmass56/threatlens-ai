# ThreatLens AI v0.9.5 Manual-UAT Remediation

The exact immutable `ThreatLensAI_v0.9.4_UAT_BASELINE.zip` passed its declared source-release integrity checks and automated deterministic release gates. End-to-end browser UAT then reproduced additional semantic, report, contract and role-aware UI defects. v0.9.5 is the corrective pre-RAG release.

| Finding | Severity | v0.9.5 control |
|---|---|---|
| No-op incident workflow request writes `incident.workflow_updated` | Medium | compare normalized before/after state and return without timestamp/audit mutation when identical |
| Incident PDF omits analyst notes and registered evidence | Medium | load persisted incident details and render notes + evidence metadata including SHA-256, registrant and timestamp |
| Report “Investigation Timeline” mixes unrelated session events with incident evidence | Medium | render incident-linked event/alert timelines per incident and separate unlinked session events under an explicit additional-analysis heading |
| 12 current rule YAML files expose obsolete `parameters.catalog_version: 0.6.0` | Medium | remove obsolete per-rule field; authoritative governed catalogue version remains v0.7.0 |
| PDF OpenAPI success response advertises `application/json` | Medium | declare `application/pdf` with binary response schema and snapshot regression |
| Built-in multi-source demo ignores analyst-supplied analysis name | Medium | preserve non-empty UI analysis name and use demo name only as fallback |
| Viewer UI exposes workflow, note and evidence mutation controls | Medium | derive Case Details capabilities from authenticated permissions/object assignment and render Viewer paths read-only; API denial remains authoritative |
| Case Details main incident and sidebar active-case/current-analysis context can disagree | Medium | bind selector to shared selected-incident state and load the incident’s persisted analysis before rerendering navigation |
| Hard browser refresh loses Streamlit authentication session | Security posture review | explicitly document server-session-only token storage; do not persist JWTs in browser localStorage or JavaScript-readable cookies |
| Streamlit evidence/telemetry upload widgets advertise the default 200 MiB cap while API enforces 10 MiB | Medium consistency | set per-widget cap from authoritative API settings and enforce exact byte boundary before evidence hashing/submission |
| Rule Catalog exposes absolute host filesystem source paths | Low/Medium information exposure | return repository-relative governed rule provenance instead of absolute paths |

Backend RBAC remained effective during UAT: Viewer workflow, note and evidence write attempts were denied and did not persist. v0.9.5 therefore corrects the misleading frontend affordances without weakening the existing API/object authorization boundary.

No database schema migration is required. Existing evidence registrant attribution is reconstructed from the immutable `incident.evidence_registered` audit provenance already stored for historical records. Alembic head remains `c31f9a7d4e20`.

RAG remains intentionally absent. v0.10 may begin only after the complete Windows release gate, external Git-archive verification, tagged archive generation and independent audit of the exact v0.9.5 artifact.
