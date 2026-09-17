# ThreatLens AI — Final Troubleshooting Guide

## First rule

Do not begin troubleshooting by deleting state.

Preserve:

- Git history;
- PostgreSQL volumes/data;
- Redis state;
- Ollama models;
- RAG vectors;
- accepted release-gate evidence;
- screenshots/presentation evidence.

Classify the failure before changing the system.

## 1. Run the canonical health checker

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

Read the first failing service or endpoint.

The expected final marker is:

```text
THREATLENS RUNTIME HEALTH: PASS
```

## 2. Docker engine unavailable

Symptom:

```text
Docker engine is not ready.
```

Check Docker Desktop / Docker Engine first. Do not alter application source to solve a stopped Docker daemon.

## 3. Core container missing or unhealthy

Core services are:

- postgres;
- redis;
- api;
- worker;
- frontend.

Inspect:

```powershell
docker compose --env-file .env.batch7.local -f compose.batch7.yml ps
```

Then inspect targeted logs for the failing service rather than dumping every environment variable.

## 4. Observability unavailable

Strict acceptance also requires:

- prometheus;
- grafana;
- postgres_exporter;
- redis_exporter.

Start the accepted observability profile:

```powershell
.\scripts\start_batch7_stack.ps1 -Observability
```

Then rerun the checker.

## 5. Frontend unavailable

Expected URL:

```text
http://127.0.0.1:8080
```

Verify the frontend container and API readiness. The frontend depends on a healthy API.

Do not expose database services to "fix" a frontend problem.

## 6. Login fails

Possible causes include:

- wrong password;
- failed-login lockout;
- disabled account;
- stale browser session;
- token rotation/revocation state.

The public login response is intentionally generic. Server-side audit/login evidence retains more specific reasons.

Avoid repeated blind login attempts because they can trigger lockout.

Use an approved local credential-recovery procedure when necessary. A recovery procedure should:

- require explicit authorization;
- avoid echoing the password;
- clear only intended lockout state;
- invalidate older tokens when appropriate;
- preserve audit evidence.

## 7. Redis / worker problem

If the API is ready but AI jobs do not progress:

- verify Redis reachability;
- verify at least one worker is registered;
- inspect worker logs;
- verify the queue is not accumulating unexpectedly.

Do not delete Redis state as the first response.

## 8. Ollama unavailable

The deterministic SOC should remain conceptually separate from AI availability.

Check:

```text
http://127.0.0.1:11434/api/tags
```

Confirm the configured models are installed and the Ollama service is running.

Accepted model names:

- `qwen3.5:4b`;
- `qwen3.5:9b`;
- `qwen3-embedding:0.6b`.

## 9. RAG not ready

The strict checker runs a live RAG verification inside the API container.

Check:

- pgvector readiness;
- embedding endpoint reachability;
- embedding model availability;
- generation model availability;
- indexed knowledge state;
- worker/runtime health.

The accepted corpus baseline is 1007 chunks, but do not hard-code that as a universal future requirement after an intentional reindex/corpus change.

## 10. AI answer is out-of-scope or partially supported

That can be correct behavior.

ThreatLens should refuse or constrain unsupported requests rather than fabricate incident facts.

Check whether:

- the selected incident is correct;
- authorized persisted evidence exists;
- the question asks for facts not present in the incident;
- citation/grounding validation rejected unsupported claims.

Do not weaken grounding just to obtain a more confident answer.

## 11. Threat Hunt shows zero

Zero results are not automatically a product defect. They can mean the current filters match nothing.

For a controlled demonstration, use an accepted query/filter combination that is known to return persisted events. Do not mutate data merely to make a screenshot look populated.

## 12. Case Operations appears empty

Case Operations requires an incident context.

Open/select an incident from Incident Queue or Case Details first so the browser route/session has an incident identifier. If the selected incident has no case-operations records, the empty state may be legitimate.

Presentation-only seeded workflow records must remain isolated from accepted Golden Demo evidence unless explicitly designed otherwise.

## 13. Temporary internet demo fails

The internet-demo launcher is branch/lineage gated and requires the official `cloudflared` client.

Do not weaken the source-lineage check.

If a tunnel is active, stop it with:

```powershell
.\STOP_THREATLENS_INTERNET_DEMO.ps1
```

The stop script validates the recorded process identity before termination.

Never kill an unrelated process based only on a reused PID.

## 14. Quick Tunnel still active after a failed gate

Use the controlled stop script and verify public revocation.

Do not leave temporary internet exposure running unattended.

## 15. Git worktree not clean

Do not automatically run `git reset --hard`.

First inspect:

```powershell
git status --short
git diff
git diff --cached
```

Determine whether changes are:

- intentional source work;
- generated build residue;
- accepted evidence/screenshots awaiting commit;
- unexpected/unrelated files.

Preserve accepted commits and evidence.

## 16. PowerShell 5.1 harness problems

Known Windows PowerShell pitfalls include:

- empty pipeline output becoming `$null`;
- `.Count`/`.Length` assumptions on scalar or special collection types;
- variable interpolation immediately before `:`;
- `Start-Process -ArgumentList` splitting messages containing spaces;
- reading redirected files while a child process still owns them;
- optional Docker `State.Health` properties.

A harness defect is not automatically a product defect.

## 17. Native stderr appears as PowerShell error records

Windows PowerShell can surface native stderr as `NativeCommandError`.

For release gates, prefer controlled `Start-Process` execution with separate stdout/stderr files and explicit exit-code checks when stderr handling matters.

## 18. Last-resort recovery

Before any destructive action:

1. capture the exact failing command/output;
2. identify the last accepted receipt/commit;
3. verify durable-state requirements;
4. decide whether the defect is source, harness, runtime/configuration or expected security behavior;
5. repair only the failing layer.

Never delete data solely to make a test green.
