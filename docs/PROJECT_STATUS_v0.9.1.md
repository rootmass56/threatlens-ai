# ThreatLens AI Project Status — v0.9.1 Release Candidate

## Status

v0.9.1 is the pre-RAG quality/security hotfix for the v0.9 service-boundary milestone. The deterministic SOC architecture remains unchanged; the hotfix closes release-integrity, RBAC acceptance, JWT bootstrap and Streamlit/API boundary findings discovered by independent full-ZIP audit.

## Retained platform capabilities

- Common security-event schema and five telemetry connector families.
- 42 governed deterministic rules / 126 fixtures.
- ATT&CK v19.1 Enterprise, Mobile and ICS catalogue awareness.
- Advanced deterministic correlation, entity resolution, semantic deduplication and persistent attack graphs.
- SQLAlchemy/Alembic persistent SOC and security models.
- FastAPI authenticated service boundary with access/refresh JWT lifecycle, Argon2id, account lockout, refresh rotation/reuse detection and revocation.
- Six governed roles with route and object authorization.
- API-backed Streamlit investigation UI.

## v0.9.1 audit-remediation state

| Finding | Remediation |
|---|---|
| Stale v0.9.0 release manifest | New deterministic v0.9.1 manifest generator/verifier; generated after all changes |
| Navigation tests outside governed matrix | Included in 52-test v0.9/v0.9.1 group |
| Incomplete six-role behavioral evidence | All six roles have navigation plus behavioral API acceptance coverage |
| Known JWT example secret accepted | Placeholder-aware validation + blank example + bootstrap rotation |
| Connector/options dropped at UI/API boundary | Per-source bounded metadata crosses multipart API boundary |
| Upload-size mismatch | UI derives canonical limits from API security-status endpoint |
| `.ndjson` UI/API mismatch | API allowlist aligned with connector support |
| Remote upload result contract mismatch | Upload UI renders API parser-statistics contract |
| Starlette plain-httpx deprecation | HTTPX2 2.7.0 added as pinned test backend |
| Release integrity not fail-fast | OpenAPI snapshot + repository hygiene + manifest verification added |

## Expected release gate

- 49 core/multi-source tests
- 23 historical release regressions
- 52 v0.9/v0.9.1 security/boundary tests
- 1 exact runtime/test pin test
- **125 total Windows governed tests**
- 39 OpenAPI paths / 40 operations
- Alembic head `b9f7d3c2a104`
- Linux `9/4/1/0`
- Multi-source `22/8/2/0`

## Next milestone rule

Do not begin v0.10 Grounded RAG until v0.9.1 passes the Windows verifier, is committed/tagged, exported with `git archive`, and the resulting ZIP passes one final independent audit.
