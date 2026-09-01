# ThreatLens AI v0.9.1 Release-Candidate Validation

## Purpose

v0.9.1 is the quality/security hotfix produced after the independent full-project audit of the immutable v0.9.0 tag. It closes the release-integrity, RBAC acceptance, JWT placeholder-secret, Streamlit/FastAPI upload-boundary, and test-governance findings before v0.10 begins.

## Source baseline

- Base release: `v0.9.0`
- v0.9.0 commit: `6448ac3ce1b23c3e1aedfe9d99d384ad51332299`
- Database schema remains unchanged.
- Alembic head remains `b9f7d3c2a104`.
- API contract remains 39 OpenAPI paths / 40 operations.

## Independent packaging-environment validation

The release candidate was validated from a clean copy of the full v0.9.0 Git-archive source tree after applying the v0.9.1 remediation.

| Gate | Result |
|---|---:|
| Python source compilation | PASS |
| Core and multi-source analytics | 49 / 49 PASS |
| v0.4 through v0.8 regressions | 23 / 23 PASS |
| v0.9/v0.9.1 auth, RBAC, UI-boundary and API-security group | 52 / 52 PASS |
| Platform-independent governed tests | 124 / 124 PASS |
| Fresh SQLite migration to `b9f7d3c2a104` | PASS |
| `alembic check` on fresh database | PASS — no new upgrade operations |
| Six-role security verifier | PASS |
| Detection-catalog verifier | PASS |
| Connector auto-detection/normalization verifier | PASS |
| Advanced correlation/attack-graph verifier | PASS |
| OpenAPI generation | PASS — 39 paths / 40 operations |
| OpenAPI committed snapshot equality | PASS |
| Release source secret/runtime-artifact cleanup | PASS |

The six-role security verifier authenticated and validated exact permission manifests for `administrator`, `analyst`, `incident_commander`, `rule_engineer`, `senior_analyst`, and `viewer`.

## Exact Windows acceptance still required

The final release tag must only be created after the candidate is installed and verified on the project's pinned Windows/Python 3.11 runtime. That gate additionally verifies the exact dependency pins, including Streamlit, FastAPI, Starlette, httpx2 and Ruff, and performs the complete ATT&CK v19.1 synchronization-backed verification.

Run on Windows from the project root:

```powershell
.\scripts\setup.ps1
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

The required terminal ending is:

```text
==================================================
All ThreatLens AI v0.9.1 verification checks passed.
==================================================
```

## v0.9.1 remediation closed by this candidate

- Release manifest is generated from the final releasable tree and is independently verified by path, byte size and SHA-256.
- Navigation RBAC tests are part of the governed matrix.
- Behavioral acceptance now covers all six roles.
- Known/example JWT secrets are rejected and `.env.example` no longer contains an accepted signing-secret placeholder.
- `.streamlit/secrets.toml` is explicitly excluded from source control/release hygiene.
- Per-source connector overrides and `analysis_year` cross the Streamlit-to-FastAPI boundary.
- UI upload limits are obtained from the API's authoritative security configuration.
- `.ndjson` is aligned across connector and upload security boundaries.
- API-instance security settings are used consistently by request dependencies.
- The API-backed upload page no longer references local-only pipeline properties.
- Starlette TestClient's new `httpx2` dependency is pinned for the governed test runtime.
- The OpenAPI snapshot and release manifest are now explicit verification gates.

## Release decision

Do not start v0.10 from this candidate merely because this document exists. First pass the exact Windows `setup.ps1` + `verify.ps1` gate, commit the verified hotfix, tag `v0.9.1`, create a Git archive from that tag, and perform the final archive audit.
