# ThreatLens AI

**Evidence-first SOC investigation platform — final release candidate documentation**

ThreatLens AI is a production-style Security Operations Center platform for ingesting security telemetry, producing deterministic detections, correlating incidents, preserving auditable case evidence, mapping activity to MITRE ATT&CK, investigating attack graphs, running governed threat-hunting and threat-intelligence workflows, and using grounded AI to explain persisted evidence.

The current source version is **0.14.0**. The repository is progressing toward a **v1.0.0 final release only after the final Phase 10 acceptance/freeze**. Do not describe the current repository as v1.0.0 until that gate passes.

## Authority model

ThreatLens is intentionally evidence-first:

1. Telemetry is parsed and normalized.
2. Deterministic rules, correlation, scoring, ATT&CK mappings, graph artifacts, notes and evidence are persisted.
3. Those persisted artifacts remain authoritative.
4. The RAG/LLM layer is downstream of authorized persisted evidence and governed knowledge.
5. AI output must not be treated as proof that an attack occurred.

This boundary is a core security invariant, not a presentation convention.

## Accepted runtime architecture

The accepted production-style local runtime uses:

- React/Vite analyst console served through Nginx on `127.0.0.1:8080`;
- authenticated FastAPI service boundary under `/api/v1`;
- PostgreSQL for durable SOC state;
- pgvector for governed RAG vectors;
- Redis for durable asynchronous AI-job delivery;
- a separate worker for AI jobs;
- Ollama-compatible local inference and embedding endpoints;
- Prometheus, Grafana, PostgreSQL exporter and Redis exporter for observability.

PostgreSQL and Redis are not directly published to the host by the accepted Compose file.

### Accepted AI profiles

| Purpose | Model / backend |
|---|---|
| Standard generation | `qwen3.5:4b` |
| Deep Analysis | `qwen3.5:9b` |
| Embeddings | `qwen3-embedding:0.6b` |
| Embedding dimensions | `1024` |
| Vector backend | `pgvector` |

The accepted runtime currently contains **1007 governed knowledge chunks**. That number is an acceptance baseline, **not a permanent invariant**; a future intentional corpus change may change it and must be re-accepted.

## Analyst capabilities

The authenticated console exposes permission-gated areas for:

- Overview and telemetry upload;
- current and historical analyses;
- incident queue and case details;
- real-time ingestion;
- advanced case operations;
- grounded AI investigation;
- attack graphs;
- MITRE ATT&CK;
- rule catalog and detection quality;
- append-oriented audit history;
- threat intelligence;
- read-only threat hunting;
- response playbooks;
- detection engineering;
- cloud / identity workflows;
- graph intelligence;
- connector health;
- reports;
- AI knowledge administration;
- security administration;
- system health.

The actual visible navigation depends on the signed-in user's permissions.

## Accepted Golden Demo

The frozen recruiter/demo storyline uses the accepted deterministic reference analysis:

| Artifact | Accepted count |
|---|---:|
| Normalized events | 10 |
| Alerts | 8 |
| Incidents | 5 |
| Quarantined records | 0 |

Use these counts only for the accepted Golden Demo reference dataset. They are not global production totals.

## Quick start — accepted local stack

### Prerequisites

- Windows 10/11
- PowerShell 5.1 or newer PowerShell
- Docker Desktop / Docker Engine with Compose
- Python where required by repository tooling
- Ollama with the configured models for live AI
- sufficient local memory for the selected Standard/Deep models

### 1. Create the ignored local environment

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\bootstrap_batch7_env.ps1
```

The generated `.env.batch7.local` contains local secrets and **must never be committed or pasted into documentation, tickets or chat**.

### 2. Start the local platform with observability

```powershell
.\scripts\start_batch7_stack.ps1 -Observability
```

### 3. Validate the complete runtime

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

Expected user-facing endpoints:

- ThreatLens console: `http://127.0.0.1:8080`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`

The application console remains authenticated.

### 4. Stop containers without deleting data

For a non-destructive stop, use Docker Compose `stop`. Do not use `down -v` for ordinary shutdown because `-v` removes named volumes.

## Demo launchers

`START_THREATLENS_DEMO.ps1` is the formal Golden Demo launcher. It validates source lineage, reuses or starts the accepted local runtime non-destructively, requires observability and AI readiness, resolves the accepted demo context, and opens the console unless `-NoBrowser` is supplied.

The Golden Demo launcher is intentionally lineage-gated to the frozen Phase 5 demo branch. Do not weaken that safety check merely to run it from a different branch.

The temporary authenticated internet demo is a **separate supervised Phase 9 workflow**. Its launcher is `START_THREATLENS_INTERNET_DEMO.ps1`, and its corresponding shutdown path is `STOP_THREATLENS_INTERNET_DEMO.ps1`. The Phase 9 workflow is intentionally branch-gated and is **not permanent hosting**.

Never leave the temporary public tunnel running unattended.

## Security posture

The accepted runtime includes, among other controls:

- authenticated API access and role/permission enforcement;
- generic unauthenticated login failures to reduce account-state enumeration;
- access/refresh token handling with refresh rotation;
- failed-login tracking and timed lockout;
- trusted-host and CORS controls;
- request-size controls;
- browser security headers;
- structured request correlation and observability;
- development API documentation disabled by default in the accepted Compose runtime;
- `no-new-privileges` container posture;
- capability dropping for API/worker containers;
- non-public internal metrics boundary;
- secret scanning, CodeQL, dependency/container scanning and SBOM workflows in the repository.

See [Final Security Model](docs/FINAL_SECURITY_MODEL.md).

## Final technical documentation

- [Final Architecture](docs/FINAL_ARCHITECTURE.md)
- [Deployment and Operations](docs/FINAL_DEPLOYMENT_AND_OPERATIONS.md)
- [Security Model](docs/FINAL_SECURITY_MODEL.md)
- [RAG / AI Architecture](docs/FINAL_RAG_AI_ARCHITECTURE.md)
- [Testing and Validation](docs/FINAL_TESTING_AND_VALIDATION.md)
- [Troubleshooting](docs/FINAL_TROUBLESHOOTING.md)

Presentation material is under `presentation/`.

## Historical documentation

The repository intentionally retains versioned historical documents and release evidence. Those files explain how ThreatLens evolved, but they must not be treated as the current runtime contract unless explicitly identified as current in the final documentation above.

When historical text disagrees with these final documents, verify against the accepted frozen source and the latest accepted release-gate evidence before making a current-state claim.

## Release discipline

The final v1.0.0 tag and final main-branch release action belong to **Phase 10**. Before Phase 10 acceptance:

- do not invent a v1.0.0 tag;
- do not rewrite accepted phase history;
- do not force-push protected release history;
- do not delete PostgreSQL/Redis/Ollama/RAG state to make a gate pass;
- do not weaken grounding, authentication, RBAC or release assertions merely to satisfy a test.
