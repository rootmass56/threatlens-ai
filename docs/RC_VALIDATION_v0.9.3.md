# ThreatLens AI v0.9.3 Release-Candidate Validation

## Purpose

v0.9.3 closes the correctness and security edge cases reproduced during the deep independent audit of the immutable v0.9.2 tagged archive. It remains the deterministic pre-RAG baseline: no generative-AI detection or RAG capability is introduced.

## Confirmed audit findings closed

- PATCH workflow requests preserve omitted fields and reject invalid transitions with a controlled conflict response.
- Incident assignment targets must exist, be active, and hold an investigator-eligible role.
- Analysis duplicate identity is semantic: content, connector selection, parser options, schema/parser/engine/correlation versions, rule profile, and the effective governed-rule hash contribute to the fingerprint.
- Timed lockout expiry resets the failed-attempt window.
- Unauthenticated login failures do not disclose disabled/locked account state.
- The in-memory limiter uses normalized policy buckets, prunes stale keys, and bounds key cardinality.
- Generated report names are collision-safe and API-generated temporary reports are deleted after the response payload is read.
- CPU-heavy synchronous analysis/persistence is offloaded from the FastAPI event loop.
- Direct runtime and development dependencies are exactly pinned and covered by the Windows runtime regression gate.
- Repository/archive hygiene rejects tracked or nested ZIP packaging artifacts.
- Current UI defaults and milestone labels no longer expose a personal analyst identity or stale v0.6 product wording.
- The legacy prototype MITRE mapper is explicitly deprecated and production modules do not import it.

## Independent validation performed on the release candidate source tree

- Python compilation: PASS.
- Core and multi-source governed tests: 49/49 PASS.
- v0.4-v0.8 regression tests: 23/23 PASS.
- v0.9-v0.9.3 security/RBAC/correctness/release tests: 71/71 PASS.
- Platform-independent governed total: 143/143 PASS.
- Fresh SQLite Alembic upgrade through `c31f9a7d4e20`: PASS.
- `alembic check`: PASS, no new upgrade operations.
- Detection catalogue: 42 governed rules / 126 fixtures PASS.
- Connector auto-detection and normalization: PASS.
- Advanced correlation and attack-graph verifier: PASS.
- Security verifier against a fresh migrated and bootstrapped database: PASS; six behavioral roles, 39 API paths, zero unprotected private operations.

## Exact Windows gate still required

The audit/container runtime cannot reproduce the project's exact Windows UI/API package set (notably Streamlit 1.61.1, FastAPI 0.141.1, Starlette 1.3.1, and Ruff 0.15.22). The final release therefore requires the authoritative Windows sequence:

```powershell
.\scripts\setup.ps1
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

Expected governed matrix: 144 tests (143 platform-independent + 1 exact runtime-pin test).

The v0.9.3 OpenAPI snapshot is based on the previously verified exact Windows v0.9.2 snapshot plus the reviewed `IncidentWorkflowRequest` schema delta. The exact Windows verifier must confirm snapshot equality before the release is tagged.

## Release rule

Do not call the candidate an immutable final release until the Windows verifier passes, the release manifest is regenerated after any Windows-runtime OpenAPI regeneration, the Git tree is clean, and the external tagged ZIP passes `scripts.verify_source_archive` with zero mismatches.
