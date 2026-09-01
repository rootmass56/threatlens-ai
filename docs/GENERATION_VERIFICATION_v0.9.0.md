# ThreatLens AI v0.9.0 Generation Verification

## Package basis

The v0.9 source package was built from the verified v0.8.0 release source plus the strict
attack-graph JSON export hotfix. The release adds the FastAPI security boundary,
authentication, six-role RBAC, persistent security state and API-backed Streamlit access.

## Verification completed in the packaging environment

The source tree was checked with the following evidence:

- Python compilation completed for `api`, `app`, `attack`, `correlation`, `core`, `database`,
  `migrations`, `scripts` and `tests`.
- A refined static import scan found no unused-import candidates in the v0.9 source and test
  files, excluding deliberate package re-exports.
- No non-migration Python source line exceeded the governed 100-character limit.
- The governed automated-test inventory contains 97 tests:
  - 49 core, persistence, rule-engine and multi-source tests;
  - 23 v0.4-v0.8 release-regression tests;
  - 24 v0.9 migration, RBAC and API-security tests;
  - 1 exact Windows runtime-pin test.
- The 96 platform-independent tests passed in isolated groups. The exact runtime-pin test is
  intentionally reserved for the target Windows virtual environment because the packaging
  container does not contain the pinned Streamlit runtime.
- A fresh empty SQLite database upgraded through every migration to `b9f7d3c2a104`.
- `alembic check` reported no model drift.
- Security bootstrap created the exact six governed roles and one active administrator.
- `python -m scripts.verify_security_api` passed all authentication, token, RBAC, OpenAPI,
  CORS, security-header, validation, route-protection and cross-user session checks.
- The protected OpenAPI contract contains 39 paths and 40 operations.

## Security-verifier acceptance

The isolated security verifier confirmed:

- Argon2id password hashes;
- JWT access and refresh tokens;
- HMAC-SHA-256 refresh-token hashes at rest;
- refresh rotation and reuse detection;
- cross-user logout rejection;
- disabled/locked account enforcement;
- exact six-role permission manifests;
- anonymous denial and viewer administration denial;
- protected OpenAPI access;
- safe validation envelopes and request identifiers;
- CORS allowlisting and response security headers;
- bearer authentication on every non-public OpenAPI operation;
- the required analysis, incident, ATT&CK, graph, report and administration routes.

## Target Windows release gate

The packaging environment does not provide PowerShell, Ruff 0.15.22, Streamlit 1.61.1,
FastAPI 0.141.1 or Starlette 1.3.1. Therefore, packaging verification does not replace the
final Windows gate.

After installation, the authoritative command is:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

It must run the exact dependency-pin test, Ruff linting and formatting, all 97 governed tests,
Alembic validation, the legacy regression suites and the v0.9 security verifier. The release
must not be committed or tagged until the script ends with:

```text
All ThreatLens AI v0.9 verification checks passed.
```
