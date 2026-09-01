# ThreatLens AI v0.13.0 â€” Batch 6 Frozen Release

## Release status
COMPLETE / FROZEN

## Batch
Batch 6 â€” Advanced SOC Capability Expansion

## Final qualification
- Final release/security gate: PASS
- Complete Python regression suite: PASS
- TypeScript production checks: PASS
- Vite production build: PASS
- Docker Compose/runtime readiness: PASS
- Alembic current == head: f6a6c0b60001
- CycloneDX v0.13.0 source SBOM: PASS
- Reviewed direct dependencies: 27
- Redis 6.4.0 represented in reviewed dependency/SBOM contract
- Machine-ingestion OpenAPI security: PASS
- Same-origin frontend/API smoke: PASS
- Local-secret hygiene: PASS

## Batch-6 capability set
- Authenticated real-time ingestion
- Threat Intelligence and IOC enrichment
- Threat Hunting
- Advanced Case Operations
- Approval-Gated Response Playbooks
- Detection Engineering / governed tuning
- Microsoft Entra ID Cloud / Identity
- Graph Intelligence and Global Search
- Durable asynchronous grounded AI preserved from Batch 5

## Important release boundary
This tag freezes the validated v0.13.0 source state. Batch 7 operational-hardening work must occur after this release boundary and must not rewrite the v0.13.0 tag.