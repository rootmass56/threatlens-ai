
# ThreatLens AI â€” Batch 5 Production Foundation

## Purpose

Batch 5 converts the verified Batch-4 RAG/security baseline into a production-oriented service topology without changing the evidence-first authority model. Deterministic detection, correlation, ATT&CK mappings, authorization, grounded generation and citation validation remain authoritative. The major architectural change is that long-running AI investigation work is moved out of the HTTP request lifecycle into durable jobs.

## Batch 5 topology

```text
Browser / React (Nginx)
        |
        | same-origin /api
        v
FastAPI -------------------- PostgreSQL
  |                              |
  |                              +-- SOC persistence
  |                              +-- audit / users / incidents
  |                              +-- durable AI jobs
  |                              +-- pgvector knowledge vectors
  |
  +---- Redis job coordinator ---- Worker
                                      |
                                      +-- authorized incident context
                                      +-- exact + semantic retrieval
                                      +-- Qwen Standard / Deep
                                      +-- structured-output validation
                                      +-- grounding / citations
                                      +-- persist result + audit
```

PostgreSQL is the system of record. Redis transports job UUIDs and worker-presence heartbeats; it is not the source of truth for incident, audit or AI results.

## Durable AI job lifecycle

Statuses are intentionally small and explicit:

- `queued` â€” persisted and awaiting a worker;
- `running` â€” claimed by one worker with a renewable database lease;
- `succeeded` â€” a grounded RAG response was persisted on the job and in existing RAG history;
- `failed` â€” bounded retries were exhausted or a terminal worker error occurred;
- `cancelled` â€” a queued job was cancelled before execution.

A running local-model request is not hard-killed because forcibly unloading an Ollama model can interfere with other investigations. Batch 5 therefore supports safe queued cancellation and documents in-flight cancellation as provider-dependent future hardening.

## Delivery and crash recovery

1. The API validates authentication, `rag:query`, `incident:read`, the incident, question and analysis mode.
2. The job row is committed before Redis delivery.
3. Redis receives only the opaque job UUID.
4. If Redis is temporarily unavailable, the PostgreSQL job remains `queued` with `queue_delivery_state=pending`.
5. The worker periodically reconciles pending database jobs and stale leases.
6. A worker atomically transitions a queued job to running in the database.
7. A heartbeat thread renews the job lease during slow Deep generation.
8. A crashed worker leaves an expiring lease. Another worker recovers/requeues the job after expiry subject to the retry budget.
9. Duplicate Redis delivery is harmless because only a database row still in `queued` state can be claimed.

## Idempotency

`POST /api/v1/incidents/{incident_uuid}/assistant/jobs` accepts an optional `Idempotency-Key`. The key is never stored in plaintext; ThreatLens persists a SHA-256 hash scoped to the actor plus a deterministic request fingerprint. Reuse with the same request returns the original job; reuse for a different request is rejected.

## API additions

- `GET /api/v1/assistant/jobs/health`
- `POST /api/v1/incidents/{incident_uuid}/assistant/jobs`
- `GET /api/v1/incidents/{incident_uuid}/assistant/jobs`
- `GET /api/v1/assistant/jobs/{job_uuid}`
- `POST /api/v1/assistant/jobs/{job_uuid}/cancel`

The historical synchronous assistant endpoint remains available for local/degraded profiles, but the Batch-5 React UI selects durable jobs whenever `THREATLENS_ASYNC_JOBS_ENABLED=1`.

## PostgreSQL and pgvector

Batch 5 promotes the existing production abstractions rather than replacing them:

- SQLAlchemy PostgreSQL URL normalization and pooling remain in `database/session.py`;
- Alembic is authoritative for the relational schema;
- `rag.vector_store.PgVectorStore` creates/uses the `vector` extension and 1024-dimensional vectors;
- exact source-ID retrieval and semantic cosine ranking retain the same public RAG semantics as the local SQLite vector backend;
- HNSW creation remains best-effort so an optional ANN-index problem cannot destroy durable vector data.

The new Alembic head is `e9b5a1300001` and adds `ai_investigation_jobs`.

## Container stack

`deploy/compose/legacy/batch5.yml` defines:

- `postgres` â€” PostgreSQL 16 + pgvector;
- `redis` â€” append-only Redis with authentication;
- `api` â€” non-root ThreatLens FastAPI image;
- `worker` â€” the same trusted code image running `python -m jobs.worker`;
- `frontend` â€” React built with Node and served through Nginx, proxying `/api` to FastAPI.

Ollama remains an external inference dependency by default and is reached through `host.docker.internal` for the Windows local profile. This avoids forcing large model layers into the application stack and preserves the option to point the same interface at a remote authenticated Ollama-compatible host later.

## Readiness

- `/api/v1/health/live` confirms the web process is alive.
- `/api/v1/health/ready` verifies PostgreSQL and, when async jobs are enabled, requires Redis connectivity and at least one visible worker heartbeat.
- `/api/v1/assistant/jobs/health` exposes queue reachability, queued count and worker presence to authorized analysts.

## Direct local staging workflow

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\bootstrap_batch5_env.ps1
.\scripts\start_batch5_stack.ps1
.\scripts\verify_batch5_live.ps1
.\scripts\initialize_batch5_rag.ps1
```

Then open `http://127.0.0.1:8080`.

## Acceptance criteria before Batch 5 can freeze

The package is implementation-complete, but the following live gates must run on the user's Windows/Docker/Ollama environment before calling Batch 5 frozen:

1. PostgreSQL migration to `e9b5a1300001` succeeds on a clean database.
2. pgvector extension initializes and governed knowledge reindexes successfully.
3. Redis is reachable and a worker heartbeat is visible.
4. Standard and Deep jobs transition `queued -> running -> succeeded` and remain visible after browser refresh/navigation.
5. Existing RAG result history/audit metadata remains intact.
6. queued-job cancellation works; running-job hard cancellation is rejected safely.
7. Redis interruption leaves jobs recoverable from PostgreSQL.
8. Worker interruption produces lease-based recovery/retry without duplicate completed queries.
9. Existing Batch-4 RAG/security regression gate still passes on the complete local source tree.
10. Frontend typecheck/build and container smoke tests pass.

Only after those live gates should `BATCH 5: FROZEN` be recorded.

## Queue capacity and backpressure

Durable AI jobs are also protected by database-authoritative capacity budgets.  The default
candidate profile allows at most 100 queued/running jobs globally and 5 active jobs per
analyst.  Idempotent replay of the same request remains allowed.  New work beyond either
budget is rejected with HTTP 429 and `Retry-After: 30`; the limit is evaluated from
PostgreSQL job state rather than Redis queue length so it remains correct during broker
recovery.

Environment controls:

- `THREATLENS_AI_MAX_ACTIVE_JOBS=100`
- `THREATLENS_AI_MAX_ACTIVE_JOBS_PER_ACTOR=5`
