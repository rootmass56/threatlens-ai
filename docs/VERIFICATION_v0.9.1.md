# ThreatLens AI v0.9.1 Verification

## Authoritative target-platform command

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

The Windows project environment remains authoritative because the release pins Python 3.11, Streamlit 1.61.1, FastAPI 0.141.1, Starlette 1.3.1, HTTPX2 2.7.0 and Ruff 0.15.22.

## Required gates

1. Compile `api`, `app`, `attack`, `config`, `correlation`, `core`, `database`, `migrations`, `rag`, `rules`, `tests` and `scripts`.
2. Ruff lint every source package plus `migrations/env.py`.
3. Ruff formatting check every source package plus `migrations/env.py`.
4. Governed 125-test Windows matrix.
5. Alembic model consistency and exact head `b9f7d3c2a104`.
6. 42 governed rules / 126 fixtures.
7. ATT&CK v19.1 Enterprise/Mobile/ICS catalogue and mapping validation.
8. Connector auto-detection/normalization.
9. Advanced correlation and attack-graph verification.
10. Authentication, token lifecycle, RBAC and API-security verification.
11. Linux `9/4/1/0` regression.
12. Multi-source `22/8/2/0` regression.
13. Package import and exact 39-path/40-operation OpenAPI snapshot check.
14. Repository tracked-file security-hygiene check.
15. Exact v0.9.1 release-manifest inventory/hash check.

## Governed test matrix

| Group | Tests |
|---|---:|
| Core and multi-source analytics | 49 |
| v0.4-v0.8 release regressions | 23 |
| v0.9/v0.9.1 auth/RBAC/navigation/API/boundary | 52 |
| Exact Windows runtime/test pins | 1 |
| **Total** | **125** |

The v0.9/v0.9.1 group explicitly includes `tests/test_v09_navigation_rbac.py` and `tests/test_v091_quality_security.py`.

## Six-role acceptance

The automated acceptance matrix authenticates all six governed roles and verifies exact persisted/returned permission manifests. It also exercises allowed and denied API behavior for analysis creation, audit access, ATT&CK synchronization, user administration and protected OpenAPI access.

## Upload-boundary acceptance

Tests verify:

- `.ndjson` alignment with connector capabilities;
- per-source connector metadata and `analysis_year` validation;
- serialization by `ThreatLensApiClient`;
- API receipt of per-source metadata;
- API-authoritative upload limits exposed to Streamlit;
- empty/unsupported/spoofed upload rejection.

## Release artifacts

Before the manifest is generated, regenerate OpenAPI:

```powershell
python -m scripts.generate_openapi_snapshot
```

After every source/document/test change is final, generate the manifest **last**:

```powershell
python -m scripts.generate_release_manifest
```

Then run the complete verifier. If the manifest or any release file is changed afterward, `scripts.verify_release_manifest` must fail until the manifest is intentionally regenerated.

## Release closure condition

Do not tag v0.9.1 unless:

- the full Windows verifier ends with `All ThreatLens AI v0.9.1 verification checks passed.`;
- no runtime secret/database/credential/generated ATT&CK material is tracked;
- the working tree is clean after the release commit;
- the fresh Git-archive ZIP passes an independent final audit.
