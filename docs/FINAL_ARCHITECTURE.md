# ThreatLens AI — Final Architecture

## Scope

This document describes the accepted production-style local architecture at source version **0.14.0**, published in the immutable **v1.0.0** project release.

## Architectural principle

ThreatLens separates **authoritative deterministic security evidence** from **assistive generative analysis**.

```text
Telemetry
   |
   v
Validation / connector parsing
   |
   v
Normalized persisted events
   |
   +--> deterministic detections --> alerts
   |                               |
   |                               v
   +--------------------------> correlation
                                   |
                                   v
                                incidents
                                   |
            +----------------------+-------------------+
            |                      |                   |
            v                      v                   v
       case evidence           ATT&CK context     attack graph
       notes / custody         governed mappings  relationships
            \                      |                   /
             \                     |                  /
              +----------- authorized context -------+
                              |
                              v
                     grounded RAG / AI
                              |
                              v
               answer + citations + limitations
```

AI is downstream. It may explain or summarize authorized evidence; it does not establish authoritative incident facts.

## Runtime topology

```text
Browser
  |
  | loopback HTTP
  v
Nginx / React frontend :8080
  |
  | same-origin /api/*
  v
FastAPI service
  |             \
  |              \ async AI jobs
  v               v
PostgreSQL       Redis ---> Worker ---> Ollama-compatible inference
  |
  +--> SOC state
  +--> audit/case state
  +--> pgvector governed knowledge
```

Observability is provided by:

```text
FastAPI internal metrics --> Prometheus :9090 --> Grafana :3000
PostgreSQL ----------------> postgres_exporter ---^
Redis ---------------------> redis_exporter ------^
```

The accepted Compose runtime does not directly publish PostgreSQL or Redis to the host.

## Service responsibilities

### Frontend

The React/Vite console is served by Nginx and is bound to `127.0.0.1:8080` in the accepted local Compose profile. The UI is authenticated and permission-aware.

The console groups capabilities into:

- SOC Operations;
- Investigation;
- Platform administration.

Navigation includes Overview, Upload & Analyze, Current Analysis, Analysis History, Incident Queue, Case Details, Real-Time Ingestion, Case Operations, AI Investigation, Attack Graph, MITRE ATT&CK, Rule Catalog, Detection Quality, Audit Trail, Threat Intelligence, Threat Hunting, Response Playbooks, Detection Engineering, Cloud / Identity, Graph Intelligence, Connector Health, Reports, AI Knowledge Admin, Security Admin and System Health.

### FastAPI

FastAPI is the authenticated service boundary. The accepted application registers router modules for:

- authentication;
- users;
- analyses;
- incidents;
- RAG;
- asynchronous jobs;
- advanced SOC capabilities;
- ATT&CK/catalog functions;
- reports;
- system/health functions.

The canonical application prefix is `/api/v1`.

Development Swagger/OpenAPI exposure is disabled by default in the accepted Compose runtime.

### PostgreSQL

PostgreSQL is the durable authority for platform state, including normalized analytics, incidents, workflow state, audit material and AI-job metadata.

### pgvector

The accepted RAG vector backend is PostgreSQL/pgvector. The embedding dimension is 1024.

The accepted knowledge baseline observed during release gates is 1007 indexed chunks. This is evidence of the accepted runtime state, not a permanent hard-coded product requirement.

### Redis and worker

Redis provides asynchronous AI-job delivery. A separate worker executes queued jobs and persists outcomes through the application data model.

The accepted runtime config bounds active AI jobs globally and per actor. These controls prevent a single actor from consuming unlimited concurrent AI capacity.

### Ollama-compatible inference

Generation and embedding are external to the API process but are reached through configured runtime endpoints.

Accepted profiles:

- Standard: `qwen3.5:4b`;
- Deep Analysis: `qwen3.5:9b`;
- embeddings: `qwen3-embedding:0.6b`.

## Evidence planes

ThreatLens deliberately distinguishes several information planes.

### Observed/persisted evidence

Examples include events, alerts, entity values, correlations, incidents and analyst-preserved case evidence. These are authoritative within the application.

### Governed knowledge

Examples include ATT&CK knowledge and reviewed security/detection documentation. Governed knowledge can provide context but must not be presented as if it were observed in the incident.

### Analyst inference

Analyst or AI interpretation must be distinguishable from observed facts.

### Threat intelligence

Threat-intelligence matches are enrichment. They remain distinct from raw observed telemetry and do not independently prove compromise.

## Investigation graph

Attack-graph relationships are persisted deterministic correlation artifacts. The graph is a visualization/investigation aid over correlated evidence and entities; it is not an LLM-generated authority layer.

## Trust boundaries

Important boundaries are:

1. browser ↔ authenticated Nginx/FastAPI application;
2. API ↔ PostgreSQL;
3. API/worker ↔ Redis;
4. API/worker ↔ Ollama-compatible inference;
5. internal metrics ↔ Prometheus;
6. local runtime ↔ temporary supervised internet tunnel, when Phase 9 is explicitly activated.

The temporary internet tunnel is not the default architecture.

## Public surfaces

Normal accepted local use is loopback-bound.

The repository also contains:

- a static public showcase for portfolio/recruiter presentation;
- a supervised temporary authenticated internet-demo workflow using a random Quick Tunnel URL.

Neither should be confused with a permanently hosted public production console.

## Source and release boundary

Current source version: **0.14.0**.

Published project release: **v1.0.0**, frozen after successful Phase 10 acceptance.

Historical architecture documents remain useful evidence of earlier releases but are not the current architecture contract.
