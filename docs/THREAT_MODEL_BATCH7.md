# ThreatLens AI Batch-7 Threat Model

## Protected assets

- analyst and administrator credentials/tokens;
- machine-ingestion credentials;
- persisted security telemetry and evidence;
- incident/case state and chain-of-custody;
- deterministic detection catalogue;
- threat-intelligence provenance;
- RAG knowledge and investigation history;
- response approval/execution records;
- PostgreSQL backups;
- release artifacts and CI credentials.

## Primary trust boundaries

1. Browser -> Nginx same-origin boundary.
2. Nginx -> FastAPI internal service.
3. Machine sender -> realtime-ingestion API.
4. FastAPI/worker -> PostgreSQL.
5. FastAPI/worker -> Redis.
6. Worker -> Ollama/inference endpoint.
7. Prometheus/exporters -> internal services.
8. GitHub Actions -> build artifacts/GHCR.

## High-priority abuse cases

- credential stuffing/account enumeration;
- JWT theft/reuse;
- oversized parser payloads;
- machine-ingestion key disclosure;
- unauthorized case/response mutation;
- direct database/Redis exposure;
- RAG prompt attempting to override evidence authority;
- queue flooding/resource exhaustion;
- log injection/high-cardinality metric abuse;
- backup theft or unreviewed destructive restore;
- dependency/CI supply-chain compromise;
- accidental secret commit.

## Batch-7 controls

- bounded rate limits and request-size ceiling;
- structured logs with request correlation;
- bounded low-cardinality metrics;
- private DB/Redis network exposure;
- non-root application container plus no-new-privileges/capability drop;
- loopback-only local UI/observability ports;
- explicit backup hash manifests and isolated restore smoke;
- reviewed dependency pins and CycloneDX source SBOM;
- CI secret/dependency/static/container scanning;
- immutable release tags; no force-push in release workflows;
- operational runbooks for failure, restore and rollback.
