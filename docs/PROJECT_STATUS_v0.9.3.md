# ThreatLens AI Project Status — v0.9.3 Final Deterministic Pre-RAG Baseline

v0.9.3 closes the confirmed runtime semantic/security defects found by deep negative testing of the v0.9.2 tagged archive. The deterministic SOC platform now includes multi-source normalization, 42 governed rules/126 fixtures, ATT&CK v19.1 all-domain catalogues, advanced correlation/attack graphs, persistent cases/evidence/audit, FastAPI authentication, six-role RBAC, semantic analysis identity and hardened release verification.

The RAG package remains a placeholder. v0.10 must not begin until the exact Windows verifier and final external tagged-ZIP audit pass.

## Exit criteria

1. 144-test Windows governed matrix passes.
2. Alembic head is `c31f9a7d4e20` with no drift.
3. 42-rule/126-fixture, ATT&CK, connector, correlation, security and regressions pass.
4. OpenAPI snapshot is exact.
5. Repository hygiene and release manifest pass.
6. Final ZIP is generated outside the repository and passes `scripts.verify_source_archive`.
7. Git tree is clean and annotated release tag points to the verified commit.
