# ThreatLens AI Project Status — v0.9.4 Pre-RAG Hardening Candidate

v0.9.4 preserves the full deterministic SOC platform while closing concurrency and database-configuration defects reproduced from the v0.9.3 tagged source archive.

Current capabilities remain: five telemetry families, Common Event Schema normalization, 42 governed rules/126 fixtures, official ATT&CK v19.1 all-domain catalogue awareness, entity/relationship correlation, persistent attack graphs, case workflow/evidence/audit, FastAPI authentication, six-role RBAC, semantic analysis identity and release-manifest/archive verification.

The current release gate targets 157 Windows tests: 49 core/multi-source + 23 v0.4-v0.8 + 84 v0.9-v0.9.4 + 1 exact runtime/build pin test. Alembic head remains `c31f9a7d4e20`; OpenAPI remains 39 paths / 40 operations.

RAG remains intentionally absent. v0.10 starts only after the tagged v0.9.4 artifact passes final independent audit.
