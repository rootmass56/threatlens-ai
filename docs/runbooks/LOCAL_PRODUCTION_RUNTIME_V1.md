# ThreatLens AI v1.0 Local Production Runtime

This runbook defines the Phase-2 controlled local runtime boundary. It intentionally reuses the accepted `threatlens-batch7` Compose project and persistent-volume names so the existing PostgreSQL, Redis, Prometheus and Grafana state is preserved while v1.0 runtime engineering continues on the separate `phase2/local-production-runtime` branch.

## Safety rules

- Never run `docker compose down -v`, `docker system prune`, `docker volume prune`, or manual volume deletion during ordinary use.
- Never operate from the frozen v0.14.0 worktree for Phase-2 development.
- `.env.batch7.local` remains local/untracked and must never be committed.
- `STOP_THREATLENS.ps1` performs a graceful `docker compose stop`; it does not delete containers, networks, images or volumes.
- `START_THREATLENS.ps1` uses the same Compose project identity (`threatlens-batch7`) and therefore reuses the accepted persistent volumes.
- AI/Ollama availability is independently reported. Deterministic SOC analytics remain available if Ollama is temporarily unavailable.

## Normal operator workflow

Start the full local platform, including observability:

```powershell
.\START_THREATLENS.ps1
```

Check the required core runtime:

```powershell
.\CHECK_THREATLENS.ps1
```

Require observability as part of the check:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability
```

Require both observability and the local Ollama endpoint:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

Stop the platform safely:

```powershell
.\STOP_THREATLENS.ps1
```

Core-only startup is available for constrained troubleshooting:

```powershell
.\START_THREATLENS.ps1 -CoreOnly
```

Use `-Build` only when source/container changes require an image rebuild:

```powershell
.\START_THREATLENS.ps1 -Build
```

## Required healthy state

The core accepted local runtime requires PostgreSQL, Redis, API, worker and frontend containers to be running/healthy; the frontend, `/api/v1/health/live` and `/api/v1/health/ready` endpoints must respond successfully; the readiness payload must report the database reachable, Redis reachable and at least one active worker.

When observability is required, Prometheus, Grafana, PostgreSQL exporter and Redis exporter must also be running, and Prometheus/Grafana health endpoints must answer successfully.

The local Ollama endpoint is checked separately so model outage does not incorrectly redefine deterministic SOC availability.