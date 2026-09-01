# ThreatLens AI v0.9.1 Release Notes

## Purpose

v0.9.1 is the quality/security hotfix that closes the independent audit findings discovered after the v0.9.0 FastAPI/RBAC release. It does not introduce RAG functionality and does not change the database schema. The Alembic head remains `b9f7d3c2a104`.

## Security hardening

- Known/example JWT signing secrets are rejected even when they satisfy the minimum character count.
- `.env.example` deliberately leaves `THREATLENS_JWT_SECRET` blank so setup/bootstrap generates a cryptographically random value.
- `.streamlit/secrets.toml` is explicitly excluded from Git.
- FastAPI dependency settings are now bound to `app.state.security_settings`, ensuring factory-created applications use their exact injected security configuration.
- Repository hygiene is verified against tracked runtime secrets, databases, credentials and downloaded/generated artifacts.

## RBAC acceptance hardening

- Navigation authorization is separated into `app/navigation_policy.py`, making the policy testable without importing Streamlit.
- Viewer, Analyst, Senior Analyst, Incident Commander, Rule Engineer and Administrator each receive explicit navigation acceptance coverage.
- All six roles receive behavioral API acceptance coverage for authentication plus privileged/denied operations.
- Object-level incident authorization tests cover all six role families where relevant.

## Streamlit/API upload contract hardening

- The API accepts bounded JSON `source_metadata` with one metadata record per uploaded file.
- `connector_id` and `analysis_year` now survive the Streamlit-to-FastAPI boundary for both single-file and multi-file analysis.
- Metadata fields, connector identifiers and source options are allowlisted and validated before deterministic analysis begins.
- `.ndjson` is accepted by the API because the registered JSON telemetry connectors already declare it as a supported extension.
- Streamlit displays and validates against upload limits returned by `/api/v1/system/security`, eliminating the previous 25 MiB UI versus 10 MiB API mismatch.
- The Upload page now renders remote pipeline statistics from the API response contract instead of assuming local-only parser properties.

## Test and release governance

The governed matrix is expanded to:

- 49 core/multi-source analytics tests;
- 23 v0.4-v0.8 regression tests;
- 52 v0.9/v0.9.1 authentication, RBAC, navigation, API and boundary tests;
- 1 exact Windows runtime/test dependency pin test.

**Total Windows governed matrix: 125 tests.**

Additional release gates verify:

- exact 39-path / 40-operation OpenAPI contract and `docs/openapi_v0.9.1.json` equality;
- repository security hygiene;
- exact v0.9.1 release-manifest file inventory, byte sizes and SHA-256 hashes.

## Dependency compatibility

The project keeps the validated FastAPI/Starlette/Streamlit versions and adds `httpx2==2.7.0` for Starlette 1.3's current TestClient backend. Plain `httpx` is no longer an explicit project dependency.

## Compatibility

v0.9.1 preserves:

- the v0.8 advanced correlation and attack-graph architecture;
- ATT&CK v19.1 catalogue/mapping behavior;
- 42 governed rules and 126 fixtures;
- Linux `9/4/1/0` regression behavior;
- multi-source `22/8/2/0` regression behavior;
- the v0.9 persistent security schema and Alembic head.

v0.10 Grounded RAG must not begin until the target Windows `scripts/verify.ps1` gate passes and the v0.9.1 release ZIP is re-audited.
