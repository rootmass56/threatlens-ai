# Migration: ThreatLens AI v0.9.4 to v0.9.5

v0.9.5 has **no database schema migration**. Alembic head remains `c31f9a7d4e20`.

Run `scripts/setup.ps1` so the exact Windows CPython 3.11 release constraints are applied, then run the complete `scripts/verify.ps1` gate.

Existing v0.9.4 analyses, incidents, notes, evidence and audit records remain valid. Evidence `registered_by` display/report provenance is derived from existing `incident.evidence_registered` audit records keyed by `evidence_uuid`; no evidence rows are rewritten.

Case Details now synchronizes the selected incident with its persisted analysis context. Viewer users receive read-only workflow/notes/evidence rendering while backend authorization remains unchanged and authoritative.

The built-in multi-source demo now preserves a non-empty analyst-supplied analysis name. Existing historical analyses keep their stored names and are not renamed.

Authentication tokens remain server-session-only in the current Streamlit profile. A hard browser refresh therefore requires sign-in again by design; v0.9.5 does not introduce browser localStorage or JavaScript-readable cookie persistence for JWTs.
