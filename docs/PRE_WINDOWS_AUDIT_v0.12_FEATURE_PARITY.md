# ThreatLens AI v0.12 — Feature-Parity RC Pre-Windows Audit

## Scope

This audit records checks that were executable on the packaging host before the source RC is handed to the target Windows/Python 3.11 workstation. It does **not** substitute for the mandatory Windows runtime, npm registry, live Ollama, TypeScript/Vite or interactive UAT gates.

## Completed packaging-host gates

- Python source compilation: **PASS**.
- Canonical FastAPI/OpenAPI contract: **PASS — 44 paths / 45 operations**.
- Reviewed direct dependency-security contract and ChromaDB absence: **PASS**.
- Streamlit-to-React feature-parity governance: **PASS — 15/15 legacy analyst surfaces migrated/superseded, 25 governed API markers, 17 workflow/integrity controls**.
- v0.12 production-web + feature-parity/data-migration tests: **25/25 PASS**.
- Core + v0.4-v0.8 tests: **72/72 PASS**.
- v0.9-v0.9.5 security/UAT/release tests: **101/101 PASS**.
- v0.10/v0.11/v0.11.1/v0.12 RAG/security/web tests: **97/97 PASS**.
- Total platform-independent governed tests exercised in isolated groups: **270/270 PASS**.
- Source CycloneDX inventory regenerated: **26 reviewed components**.
- Release-manifest integrity verification: **PASS** after final source assembly.
- Frontend TypeScript source syntax/local-type smoke check with temporary packaging-host stubs: **PASS**. This is not the authoritative npm/React typecheck.

## Mandatory target-Windows gates

The target workstation must still run `INSTALL_THREATLENS_V012_AND_VERIFY.ps1`, which requires:

- CPython 3.11 exact runtime/dependency pin test, bringing the governed Windows matrix to **271/271**;
- Ruff 0.15.22 lint and formatting checks;
- exact installed transitive dependency attestation and fresh online OSV audit;
- real npm lockfile resolution;
- real React/@types/Vite TypeScript project-reference typecheck;
- real Vite production build;
- npm high/critical vulnerability audit;
- live Qwen3.5 4B/9B + Qwen embedding/Ollama readiness;
- local React feature-parity UAT and optional guarded v0.11.1 operational-data migration.

Only after those pass should `FREEZE_THREATLENS_V012_FEATURE_PARITY.ps1` be used. Production deployment remains a subsequent gated phase.
