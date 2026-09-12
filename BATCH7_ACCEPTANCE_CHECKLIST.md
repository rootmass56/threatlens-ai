# ThreatLens AI v0.14.0 — Batch 7 Acceptance Checklist

## 7A Observability
- [ ] structured API logs proven
- [ ] structured worker logs proven
- [ ] request IDs correlate logs
- [ ] Prometheus scrapes API/PostgreSQL/Redis
- [ ] Grafana dashboard loads
- [ ] slow request and 5xx metrics observable

## 7B Performance / concurrency
- [ ] bounded load probe executed
- [ ] success rate recorded
- [ ] p50/p95/p99 recorded
- [ ] measured throughput recorded
- [ ] concurrent authenticated requests tested
- [ ] AI queue pressure/recovery tested

## 7C PostgreSQL / pgvector
- [ ] Alembic current=head `b7f1c2d30001`
- [ ] operational indexes present
- [ ] PostgreSQL performance audit captured after realistic activity
- [ ] pgvector governed retrieval remains correct

## 7D Backup / restore / DR
- [ ] backup created with SHA-256 manifest
- [ ] isolated restore smoke passes
- [ ] timed backup/restore evidence captured
- [ ] preliminary RPO/RTO documented from measurement

## 7E Security hardening
- [ ] static Batch-7 security audit passes
- [ ] database/Redis remain unexposed
- [ ] local web/metrics/dashboard ports bind to loopback
- [ ] no-new-privileges/cap-drop effective for application services
- [ ] request body ceiling verified
- [ ] HSTS behavior reserved for HTTPS profile
- [ ] RBAC regression passes

## 7F Supply chain / DevSecOps
- [ ] dependency baseline exact
- [ ] CycloneDX v0.14.0 source SBOM exact
- [ ] secret scan passes
- [ ] dependency audit passes
- [ ] container HIGH/CRITICAL policy passes or reviewed exception is documented
- [ ] CodeQL workflow enabled

## 7G CI/CD
- [ ] PR/push CI green
- [ ] immutable SHA-tagged image build proven
- [ ] no production deployment from developer working tree

## 7H Runbooks / freeze
- [ ] all operational runbooks reviewed
- [ ] complete Python suite passes
- [ ] frontend typecheck/build passes
- [ ] Docker/container smoke passes
- [ ] Batch-6 capability regression passes
- [ ] final v0.14.0 gate receipt created
- [ ] release commit/tag/archive created only after all above PASS
