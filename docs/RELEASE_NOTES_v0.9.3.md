# ThreatLens AI v0.9.3 Release Notes

v0.9.3 is the deterministic correctness/security closure before the v0.10 grounded-RAG milestone. It does not introduce an LLM or change the v0.8 correlation model. It strengthens the trusted evidence and case-management foundation that RAG will later consume.

## Runtime correctness fixes

- PATCH updates preserve omitted incident fields; explicit `assignee: null` remains an intentional unassignment request subject to assignment permission.
- Assignment targets must exist, be active and hold an investigator-eligible role (`analyst`, `senior_analyst`, `incident_commander`, or `administrator`).
- Invalid workflow transitions return a controlled `409 workflow_update_failed` envelope rather than surfacing as an internal error.
- Analysis duplicate prevention now uses a semantic fingerprint, not raw bytes alone.
- Timed lockout expiry resets the failure window before the next attempt.
- Disabled/locked/nonexistent login attempts receive the same unauthenticated failure envelope while precise reasons remain in server-side audit/login-attempt evidence.
- Generic rate limiting uses normalized policy buckets and bounded key cardinality.
- PDF report generation uses collision-safe names; API-generated temporary files are deleted after reading.
- CPU-heavy deterministic analysis/persistence executes through Starlette's threadpool from the async upload endpoint.

## Persistence

Alembic head: `c31f9a7d4e20`.

New `analysis_sessions` fields:

- `analysis_fingerprint` — indexed SHA-256 of canonical semantic analysis context;
- `analysis_context_json` — evidence hashes, filenames, requested/resolved connectors, parser options, application/engine/parser/schema/correlation versions, rule profile and effective governed-rule hash.

Legacy sessions remain readable. New duplicate decisions are made only against the stronger semantic fingerprint.

## Release hardening

- all direct runtime/dev dependencies are exact-pinned;
- any tracked `.zip` artifact is forbidden by repository hygiene;
- the source archive verifier rejects nested ZIPs;
- personal/default analyst identity and stale Detection Quality v0.6 presentation labels are removed;
- the historical `core.mitre_mapper` compatibility module is explicitly deprecated and verified unused by production modules.

## Verification

The governed Windows matrix is 144 tests: 49 core/multi-source + 23 v0.4-v0.8 + 71 v0.9-v0.9.3 + 1 exact runtime dependency test.
