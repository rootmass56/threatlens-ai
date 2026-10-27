# ThreatLens AI — Final Deployment and Operations

## Supported final-project operating model

The accepted final-project runtime is a **production-style local Docker Compose deployment** on Windows, with optional supervised temporary internet exposure for a demo.

It is not documented as a permanently hosted public SOC service.

## Prerequisites

- Windows 10/11
- PowerShell 5.1 or newer PowerShell
- Docker Desktop / Docker Engine with Compose
- Ollama for live Standard/Deep generation and embeddings
- the required local models
- adequate RAM/disk for PostgreSQL, Docker images, models and observability data

## Local secret bootstrap

From the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\bootstrap_batch7_env.ps1
```

This creates `.env.batch7.local` when one does not already exist.

The file contains generated runtime secrets and is intentionally ignored. Never commit it, attach it to reports, paste it into tickets, or place its values in screenshots.

The bootstrap script does not print generated passwords/secrets.

## Start the complete local stack

```powershell
ollama pull qwen3.5:4b
ollama pull qwen3.5:9b
ollama pull qwen3-embedding:0.6b
.\START_THREATLENS.ps1 -RequireAI
```

Run the model pulls once on a new machine. The start script starts/reuses Docker Desktop and Ollama when needed, then brings up the core and observability services. If the models are not needed, omit `-RequireAI`; deterministic SOC features remain available. `scripts/start_batch7_stack.ps1 -Observability` is the lower-level stack launcher used by specialized workflows.

The accepted Compose service set includes:

- `postgres`
- `redis`
- `api`
- `worker`
- `frontend`
- `prometheus`
- `grafana`
- `postgres_exporter`
- `redis_exporter`

A `syslog_collector` service exists behind its dedicated Compose profile.

## Validate readiness

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

The strict checker validates:

- PostgreSQL;
- Redis;
- API;
- worker;
- frontend;
- Prometheus;
- Grafana;
- exporters;
- frontend endpoint;
- API liveness/readiness;
- Ollama reachability;
- grounded-RAG live readiness.

Expected final marker:

```text
THREATLENS RUNTIME HEALTH: PASS
```

## Local endpoints

| Surface | Local address |
|---|---|
| ThreatLens console | `http://127.0.0.1:8080` |
| Prometheus | `http://127.0.0.1:9090` |
| Grafana | `http://127.0.0.1:3000` |
| Ollama default host endpoint | `http://127.0.0.1:11434` |

PostgreSQL and Redis are not published as normal host ports in the accepted Compose file.

## Authentication

The console requires an authorized ThreatLens user account.

Do not add passwords to launch scripts or documentation. If a credential must be reset during local administration, use a purpose-built recovery process that preserves the security audit trail and avoids printing/persisting the password.

## Demonstrations: choose the correct dataset

From current post-release `main`, use the [Enhanced Golden Demo v2](../demo/README_ENHANCED_DEMO_V2.md) for the five-source portfolio scenario (`29` events, `26` alerts, `2` incidents, `0` quarantined):

```powershell
.\scripts\demo\start-enhanced-demo-v2.ps1
```

Those counts are the locked v2 fixture, not global platform totals. It does not change the immutable v1.0.0 release reference.

### Frozen v1 acceptance demo

The formal Golden Demo launcher is:

```powershell
.\scripts\demo\start-golden-demo.ps1
```

It:

- checks source lineage;
- reuses a healthy runtime when possible;
- starts/reuses services non-destructively;
- requires observability and AI readiness;
- resolves the accepted Golden Demo analysis/incident context;
- prints the demo order;
- opens the browser unless `-NoBrowser` is supplied.

The launcher is intentionally gated to its frozen Phase 5 source lineage. It is **not** the current-main v2 entrypoint. Use it as a formal acceptance/demo workflow from the branch it requires; do not remove that control just to bypass a branch mismatch. Its reference dataset is `10` events, `8` alerts, `5` incidents, `0` quarantined.

## Temporary supervised internet demo

The Phase 9 internet-demo workflow is intentionally separate from normal local operation.

Start, only from the accepted Phase 9 branch/worktree:

```powershell
.\scripts\demo\start-internet-demo.ps1
```

The workflow creates a random `trycloudflare.com` Quick Tunnel, validates the HTTPS/security boundary and records the exact `cloudflared` process identity.

When the supervised demonstration is finished, stop it using:

```powershell
.\scripts\demo\stop-internet-demo.ps1
```

The shutdown script validates the recorded process before terminating it, verifies the public endpoint is no longer operational, verifies the local application remains healthy, and removes only ephemeral active-tunnel state.

**Never leave the temporary tunnel running unattended.**

## Normal shutdown

For ordinary local shutdown, prefer stopping containers without deleting volumes.

Do not use destructive recovery commands such as:

```text
docker compose down -v
```

unless an explicitly approved operation requires deleting data. The accepted project preserves PostgreSQL, Redis, model and RAG state across normal restarts.

## Observability

Prometheus and Grafana are part of the accepted observability profile.

The FastAPI `/internal/metrics` endpoint is intended for the internal container-network scrape path and is not proxied through the normal public `/api/` frontend boundary.

## Backup and restore

The repository contains operational backup/restore tooling from the hardening phase, including:

- `scripts/backup_batch7.ps1`
- `scripts/restore_batch7_smoke.ps1`

Use isolated restore smoke tests before any approved real restore. Never overwrite durable production-style state merely to make a release gate pass.

## Logs

Use Docker Compose logs for diagnosis. Avoid copying complete environment dumps into evidence because environment variables may contain secrets.

Prefer targeted service logs and request IDs.

## Upgrade / rebuild discipline

For ordinary troubleshooting:

- preserve PostgreSQL volumes;
- preserve Redis data;
- preserve Ollama models;
- preserve accepted RAG vectors;
- preserve release-gate evidence;
- diagnose source/harness/runtime defects before rebuilding.

A rebuild is not equivalent to a data reset.

## Release branch discipline

Phase-specific launchers may enforce exact branches or ancestry. Those checks are intentional.

Phase 10 completed the v1.0.0 release through protected PR #18. The existing v1.0.0 tag is immutable and must not be moved, recreated or retargeted.
