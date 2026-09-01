# ThreatLens AI v0.12 — React SOC Feature-Parity Gate

## Release rule

ThreatLens v0.12 must not replace the legacy Streamlit console with a visually cleaner but functionally weaker shell. The production React/Vite console therefore has a governed parity inventory in `config/frontend_feature_parity_v0.12.json`, verified by `python -m scripts.verify_frontend_feature_parity` during the release gate.

## Migrated workflows

| Legacy Streamlit workflow | React production workflow | Parity / improvement |
| --- | --- | --- |
| Overview | Overview | Persisted posture, incident queue, RAG/runtime and recent analyses |
| Upload & Analyze | Upload & Analyze | Multi-file upload, API limit checks, per-file connector metadata, Linux analysis year and diagnostic preview |
| Current Analysis | Current Analysis | Sources, normalized events, alerts, incidents, timeline, quarantine and correlation evidence |
| Analysis History | Analysis History | Search, persisted-session selection and export |
| Incident Queue | Incident Queue | Status/search filtering, export and case navigation |
| Case Details | Case Details | Object-aware workflow, evidence/events, entities/relationships, notes, evidence registry and case audit |
| AI Assistant | AI Investigation | Auto/Standard/Deep, routing, fallback transparency, citation planes, grounding diagnostics and history |
| Audit Trail | Audit Trail | Searchable/exportable records with RBAC-scoped access |
| Rule Catalog | Rule Catalog | Governed rule definition, validation and fixture evidence |
| Detection Quality | Detection Quality | Quality summary, per-rule governance and profiles |
| ATT&CK Coverage | MITRE ATT&CK | Enterprise/Mobile/ICS awareness, techniques, mappings, gaps, STIX inventory, Navigator and governed sync |
| Attack Graph | Attack Graph | Dedicated analysis selector, interactive node/confidence filters, graph/table/JSON/CSV evidence |
| Connector Health | Connector Health | Registry, coverage and safe file diagnostics |
| Reports | Reports | Authenticated PDF generation plus independent browser verification of the server SHA-256 digest |
| AI Knowledge Admin | AI Knowledge Admin | RAG health/status and permission-aware incremental/forced re-index |
| Security Administration | Security Admin | Users, roles, create/update/password/activation/unlock/session-revocation lifecycle, security posture and protected OpenAPI |

## Authorization parity

React consumes the `permissions` manifest returned by ThreatLens authentication and uses it to hide actions a role cannot perform. This improves operator experience but **does not replace API authorization**. Every privileged mutation remains enforced by FastAPI/RBAC and object-level case rules.

The React case workflow mirrors the server's allowed status transitions and self/any-case semantics so analysts are not offered impossible transitions or arbitrary assignment controls. Case audit records are removed server-side from incident-detail responses when the principal lacks `audit:read`.

## Evidence and report integrity

Evidence files selected in the Case workspace are size-checked against `/api/v1/system/security`, SHA-256 hashed in the browser and never uploaded to the evidence-metadata endpoint. The generated digest, description and source reference are sent to FastAPI.

Downloaded PDF reports are independently SHA-256 hashed in the browser. If FastAPI supplies `X-Content-SHA256` and the local digest differs, React refuses the download.

## Operational-data continuity

`MIGRATE_V0111_DATA_TO_V012.ps1` runs a dry-run by default. The migration validates SQLite integrity, exact operational schemas and the compatible Alembic head; creates a pre-migration backup when applying; migrates operational analysis/case/correlation/RAG history; and deliberately preserves v0.12 users, password hashes, roles, refresh tokens, login-attempt state and current ATT&CK catalogue state.

## Streamlit disposition

`app/` stays in v0.12 as historical/regression/reference code. Production deployment uses React/Vite + FastAPI. Passing feature parity means Streamlit is no longer required for normal analyst or administrator workflows.

## Final phase gate

This phase is complete only after:

- `python -m scripts.verify_frontend_feature_parity` passes;
- the governed Windows matrix reports **271/271**;
- TypeScript project-reference checking passes;
- Vite production build passes;
- npm high/critical audit passes;
- a v0.11.1 operational-data migration dry-run passes, and data is either migrated or consciously waived for a clean deployment;
- full local React UAT is completed using the supplied checklist;
- the final release manifest reports zero mismatches.
