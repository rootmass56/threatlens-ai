# ThreatLens AI v0.14.0 — Batch 7 START HERE

This archive is the **Batch 7 Operational Hardening release candidate** built on the frozen v0.13.0 / Batch 6 capability boundary.

**Do not modify or retag the frozen v0.13.0 Git release.** Work in this extracted Batch-7 directory and freeze v0.14.0 only after every Batch-7 acceptance item passes.

## Recommended Windows path

`D:\projects\ThreatLensAI_v0.14_BATCH7_OPERATIONAL_HARDENING_RC_FULL`

## Exact order

1. Extract this ZIP into the recommended path.
2. Run `INSTALL_AND_STATIC_VERIFY_BATCH7.ps1`.
3. Run `scripts\MIGRATE_BATCH6_DATA_TO_BATCH7.ps1 -StartObservability` to copy the frozen Batch-6 PostgreSQL state into isolated Batch-7 volumes.
4. Run `scripts\verify_batch7_live.ps1 -RequireObservability`.
5. Complete the measured 7B load probes, 7C DB audit, 7D backup/restore smoke, 7E security audit, 7F CI/security scans, 7G GitHub Actions validation and 7H runbook/final-freeze gates.
6. Freeze/tag v0.14.0 only after `BATCH7_ACCEPTANCE_CHECKLIST.md` is fully PASS.

## Batch 7 phases packaged

- **7A Observability:** structured logs, request correlation, Prometheus, Grafana, PostgreSQL/Redis exporters.
- **7B Performance/concurrency:** bounded load tooling with throughput and p50/p95/p99 measurement.
- **7C Database/pgvector:** operational indexes and performance audit tooling.
- **7D Backup/restore/DR:** PostgreSQL backup, SHA-256 manifests, isolated restore smoke and guarded restore.
- **7E Security hardening:** request ceilings, headers/HSTS profile, container hardening and security audit.
- **7F DevSecOps:** reviewed dependencies, v0.14 CycloneDX SBOM and scan workflows.
- **7G CI/CD:** GitHub Actions gates and immutable GHCR image publication by commit SHA.
- **7H Operations/freeze:** operational runbooks, final live/regression gates and v0.14 freeze checklist.

## Package verification performed before ZIP creation

- Python syntax/compile check: PASS.
- `python -m scripts.verify_batch7_release`: PASS.
- `tests/test_batch7_operational_hardening.py`: **15/15 PASS** in the packaging environment.
- Governed rule contract reported by Batch-7 release verifier: **46 rules / 138 fixtures PASS**.
- Complete Windows/Docker/live acceptance is intentionally **not claimed by the archive itself**. It must be run on the target Windows/Docker environment before v0.14.0 freeze.

## Key files

- `compose.batch7.yml`
- `.env.batch7.example`
- `scripts\bootstrap_batch7_env.ps1`
- `scripts\MIGRATE_BATCH6_DATA_TO_BATCH7.ps1`
- `scripts\start_batch7_stack.ps1`
- `scripts\verify_batch7_static.ps1`
- `scripts\verify_batch7_live.ps1`
- `scripts\backup_batch7.ps1`
- `scripts\restore_batch7_smoke.ps1`
- `ops\load\batch7_load.py`
- `ops\db\performance_audit.py`
- `ops\security\batch7_security_audit.py`
- `.github\workflows\batch7-ci.yml`
- `.github\workflows\batch7-ghcr.yml`
- `.github\workflows\codeql.yml`
- `BATCH7_ACCEPTANCE_CHECKLIST.md`
