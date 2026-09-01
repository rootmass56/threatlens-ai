
# ThreatLens Batch 5 Deployment Runbook

## Prerequisites

- Windows 10/11 with Docker Desktop and Compose v2;
- local Ollama reachable from the host on port 11434, or a compatible remote inference endpoint;
- Qwen Standard, Deep and embedding models already available to the inference host;
- enough disk for PostgreSQL/Redis persistent volumes and container images.

## 1. Generate local staging secrets

Run:

```powershell
.\scripts\bootstrap_batch5_env.ps1
```

This creates `.env.batch5.local`, which is Git-ignored. Preserve the generated admin password securely.

## 2. Start the stack

```powershell
.\scripts\start_batch5_stack.ps1
```

The API container performs Alembic migrations and security bootstrap before Uvicorn starts. The worker waits for healthy PostgreSQL, Redis and API services.

## 3. Verify infrastructure

```powershell
.\scripts\verify_batch5_live.ps1
```

Expected final status: `THREATLENS BATCH 5 LIVE INFRASTRUCTURE: PASS`.

## 4. Build the production vector index

```powershell
.\scripts\initialize_batch5_rag.ps1
```

This invokes the existing governed knowledge indexer inside the API container while `THREATLENS_RAG_VECTOR_BACKEND=pgvector`. It requires the configured embedding model to be reachable.

## 5. Browser UAT

Open `http://127.0.0.1:8080` and sign in with the generated administrator account. On AI Investigation the UI should show durable jobs enabled, Redis connected and at least one worker.

Run a Standard job and verify:

```text
queued -> running -> succeeded
```

Navigate away while it runs, refresh, then return. The job and result must still be present.

Run one Deep job and repeat the same persistence test. The browser is no longer required to keep one long HTTP request open.

## 6. Failure UAT

### Redis interruption

Stop Redis while the API remains available, submit a job and confirm the database job is retained with pending delivery. Restore Redis/worker and confirm reconciliation eventually executes it.

### Worker interruption

Stop the worker after it claims a controlled test job. After the configured lease expires, restart a worker and verify the database job is recovered/retried subject to the attempt budget.

Do not use an expensive 9B request for repeated crash tests unless necessary.

## 7. Stop the stack

```powershell
.\scripts\stop_batch5_stack.ps1
```

Docker volumes are intentionally preserved. Use `docker compose ... down -v` only when you explicitly intend to delete PostgreSQL/Redis staging data.

## Security notes

- Do not commit `.env.batch5.local`.
- Do not expose PostgreSQL or Redis host ports by default.
- Do not place JWT, database or Redis secrets in frontend environment variables.
- The Nginx frontend is the only host-published service in the default Compose topology.
- PostgreSQL is the system of record; Redis data loss must not erase incident or AI job history.

## Queue backpressure acceptance

The default Batch-5 profile caps active durable AI jobs at 100 globally and 5 per analyst.
If either budget is reached the API returns HTTP 429 with `Retry-After: 30`.  Adjust the
limits only after measuring the database, worker and inference capacity of the deployment.
