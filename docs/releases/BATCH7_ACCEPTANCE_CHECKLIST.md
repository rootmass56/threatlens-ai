# ThreatLens AI v0.14.0 — Batch 7 Acceptance Checklist

> Historical acceptance record. All Batch 7 sections were completed before the protected v0.14.0 and v1.0.0 release line. Authoritative evidence remains in the release receipts and CI history; this matrix is retained for regression traceability.

## 7A Observability
- [x] structured API logs proven
- [x] structured worker logs proven
- [x] request IDs correlate logs
- [x] Prometheus scrapes API/PostgreSQL/Redis
- [x] Grafana dashboard loads
- [x] slow request and 5xx metrics observable

## 7B Performance / concurrency
- [x] bounded load probe executed
- [x] success rate recorded
- [x] p50/p95/p99 recorded
- [x] measured throughput recorded
- [x] concurrent authenticated requests tested
- [x] AI queue pressure/recovery tested

## 7C PostgreSQL / pgvector
- [x] Alembic current=head `b7f1c2d30001`
- [x] operational indexes present
- [x] PostgreSQL performance audit captured after realistic activity
- [x] pgvector governed retrieval remains correct

## 7D Backup / restore / DR
- [x] backup created with SHA-256 manifest
- [x] isolated restore smoke passes
- [x] timed backup/restore evidence captured
- [x] preliminary RPO/RTO documented from measurement

## 7E Security hardening
- [x] static Batch-7 security audit passes
- [x] database/Redis remain unexposed
- [x] local web/metrics/dashboard ports bind to loopback
- [x] no-new-privileges/cap-drop effective for application services
- [x] request body ceiling verified
- [x] HSTS behavior reserved for HTTPS profile
- [x] RBAC regression passes

## 7F Supply chain / DevSecOps
- [x] dependency baseline exact
- [x] CycloneDX v0.14.0 source SBOM exact
- [x] secret scan passes
- [x] dependency audit passes
- [x] container HIGH/CRITICAL policy passes or reviewed exception is documented
- [x] CodeQL workflow enabled

## 7G CI/CD
- [x] PR/push CI green
- [x] immutable SHA-tagged image build proven
- [x] no production deployment from developer working tree

## 7H Runbooks / freeze
- [x] all operational runbooks reviewed
- [x] complete Python suite passes
- [x] frontend typecheck/build passes
- [x] Docker/container smoke passes
- [x] Batch-6 capability regression passes
- [x] final v0.14.0 gate receipt created
- [x] release commit/tag/archive created only after all above PASS
