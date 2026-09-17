# ThreatLens AI v1.0 Local Production Runtime

This runbook defines the controlled local runtime for the final ThreatLens AI v1.0 engineering path. It intentionally reuses the accepted `threatlens-batch7` Compose project and persistent-volume names so PostgreSQL, Redis, Prometheus and Grafana state remain continuous while development proceeds on `phase2/local-production-runtime`.

## Safety rules

- Never run `docker compose down -v`, `docker system prune`, `docker volume prune`, or manual volume deletion during ordinary use.
- Never use the frozen v0.14.0 worktree for Phase-2 development.
- `.env.batch7.local` remains local/untracked and must never be committed.
- `STOP_THREATLENS.ps1` performs graceful `docker compose stop`; it does not delete containers, networks, images or volumes.
- `START_THREATLENS.ps1` retains Compose project identity `threatlens-batch7`, so accepted persistent volumes are reused.
- Deterministic SOC analytics remain usable when Ollama is unavailable unless the operator explicitly requires AI readiness.

## Normal operation

Start the full deterministic SOC runtime:

```powershell
.\START_THREATLENS.ps1
```

Start the full runtime and require live AI/RAG readiness:

```powershell
.\START_THREATLENS.ps1 -RequireAI
```

The `-RequireAI` path verifies more than the Ollama HTTP endpoint. It runs the governed `scripts.verify_rag_runtime --require-ready` smoke inside the API container, requiring configured RAG health, vector readiness, indexed knowledge, the embedding path, retrieval, Standard model generation, and availability of both Standard and Deep model profiles.

Check core runtime:

```powershell
.\CHECK_THREATLENS.ps1
```

Check observability:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability
```

Check the complete local product runtime including live grounded RAG:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

Stop safely:

```powershell
.\STOP_THREATLENS.ps1
```

## Recovery convenience

`START_THREATLENS.ps1` now checks the Docker engine first. If Docker Desktop is installed but the engine is not running, the launcher attempts to start Docker Desktop and waits for the engine.

When `-RequireAI` is supplied, the launcher also checks the local Ollama endpoint. If Ollama is unavailable, it attempts to locate `ollama.exe`, starts `ollama serve`, waits for readiness, then performs the live governed RAG smoke.

This behavior is intentionally local and recovery-oriented. It does not install software, pull new models, modify the RAG index, alter database rows, or change persistent volumes.

## Required healthy state

Core acceptance requires PostgreSQL, Redis, API, worker and frontend to be running/healthy; the frontend, `/api/v1/health/live` and `/api/v1/health/ready` endpoints must succeed; readiness must report database reachable, Redis reachable and at least one active worker.

Observability acceptance additionally requires Prometheus, Grafana, PostgreSQL exporter and Redis exporter.

AI/RAG acceptance additionally requires the existing governed external runtime to be fully ready and to pass a live embedding -> vector retrieval -> structured model generation smoke. No knowledge reindex is performed by these runtime controls.

## Reboot acceptance

Phase 2C establishes recovery-aware launchers and exact AI/model readiness. The actual Windows reboot/persistence proof is performed as the final Phase 2D gate:

1. record the accepted pre-reboot database/volume/RAG baseline;
2. reboot Windows;
3. run `START_THREATLENS.ps1 -RequireAI`;
4. verify core + observability + AI/RAG;
5. compare persistent state with the pre-reboot checkpoint;
6. close Phase 2 only after exact continuity is proven.