# ThreatLens AI — Final Demo and Interview Guide

## Purpose

This guide is for recruiter demonstrations, technical interviews, project reviews and viva-style explanations of ThreatLens AI. Choose the current enhanced portfolio scenario or the frozen v1 acceptance reference explicitly; do not combine their figures.

Current source version: **0.14.0**.

Published project release: **v1.0.0**, frozen after successful Phase 10 acceptance through protected PR #18.

Current `main` may include later repository-presentation maintenance; do not describe those later changes as part of the immutable v1.0.0 snapshot.

## One-sentence project description

ThreatLens AI is an evidence-first SOC investigation platform that ingests security telemetry, performs deterministic detection and correlation, preserves auditable investigation context, maps activity to MITRE ATT&CK, supports case operations and threat hunting, and uses grounded AI only after authoritative evidence has been persisted.

## 30-second elevator pitch

ThreatLens AI is designed around a simple rule: **AI does not establish the incident facts**. The platform first normalizes telemetry, runs deterministic detection and correlation, persists incidents and investigation evidence, and then allows an authenticated analyst to use local grounded AI against that authorized context. The runtime uses FastAPI, React/Nginx, PostgreSQL, pgvector, Redis workers, local Qwen models and Prometheus/Grafana. The current enhanced portfolio fixture contains 29 normalized events, 26 alerts and 2 correlated incidents across five sources; these are dataset-specific results, not platform-wide totals.

## Architecture talking points

Use these points when asked to explain the system:

1. **Frontend** — React/Vite console served by Nginx.
2. **API** — authenticated FastAPI service boundary under `/api/v1`.
3. **Durable state** — PostgreSQL.
4. **Vector retrieval** — pgvector in PostgreSQL.
5. **Async AI delivery** — Redis plus a separate worker.
6. **Local AI** — Standard `qwen3.5:4b`, Deep Analysis `qwen3.5:9b`, embeddings `qwen3-embedding:0.6b`.
7. **Observability** — Prometheus, Grafana, PostgreSQL exporter and Redis exporter.
8. **Security boundary** — RBAC, authenticated API, security headers, lockout/token controls, secret hygiene and controlled exposure.
9. **Evidence invariant** — deterministic persisted evidence is authoritative; AI is assistive and downstream.

See [Final Architecture](FINAL_ARCHITECTURE.md) and [Final Security Model](FINAL_SECURITY_MODEL.md).

## Current enhanced portfolio demonstration (v2)

From current post-release `main`, use [`start-enhanced-demo-v2.ps1`](../scripts/demo/start-enhanced-demo-v2.ps1) and follow the [enhanced walkthrough and acceptance contract](../demo/README_ENHANCED_DEMO_V2.md). It uses five supported telemetry sources and a synthetic multi-stage intrusion. The locked result is 29 events, 26 alerts, 2 critical incidents, and 0 quarantined records.

Recommended concise tour: Overview → Current Analysis → Incident Queue/Case Details → ATT&CK/Attack Graph → AI Investigation (saved answer and citations) → Audit/System Health. If time permits, include threat intelligence, hunting, case operations, and the permissioned response record. Explain that AI output is advisory and that IOC enrichment is not observed incident fact.

## Frozen v1 acceptance reference (different dataset)

The frozen reference analysis used in the recruiter storyline contains:

| Metric | Accepted value |
|---|---:|
| Normalized events | 10 |
| Alerts | 8 |
| Correlated incidents | 5 |
| Quarantined records | 0 |

These numbers belong to the accepted Golden Demo dataset. They are not total lifetime platform counts.

## Frozen v1 reference walkthrough (historical)

### 1. Public showcase

Use the static showcase to explain the project at a high level without exposing the operational backend.

Message:

> This is the public portfolio surface. The authenticated SOC console is separate.

### 2. Secure login

Show that the operational console is authenticated.

Do not expose passwords, bearer tokens, `.env` files, terminal secrets or private keys.

### 3. SOC Overview

Show:

- persisted analyses;
- active incidents;
- high-priority incidents;
- RAG readiness;
- detection governance;
- telemetry connectors;
- AI runtime.

Message:

> The platform is not just a chatbot. The AI layer is one component downstream of persisted SOC evidence.

### 4. Current Analysis

Open the accepted multi-source Golden Demo analysis.

Show:

- 10 events;
- 8 alerts;
- 5 incidents;
- parse success;
- source/session metadata.

Message:

> The reference story is deterministic and persisted before AI is involved.

### 5. Incident Queue and Case Details

Open a representative accepted incident.

Show:

- status/priority/severity/risk;
- narrative;
- correlation context;
- evidence;
- workflow/audit tabs where appropriate.

Message:

> The incident is an application artifact backed by persisted detection/correlation evidence.

### 6. MITRE ATT&CK and Attack Graph

Show governed ATT&CK context and the persisted attack graph.

Message:

> ATT&CK provides governed contextual mapping. The attack graph is a deterministic correlation artifact over incidents, alerts, entities and techniques.

### 7. Threat Intelligence

Show feeds/indicators/hits.

Message:

> Threat intelligence is enrichment. A hit is not automatically proof of compromise.

### 8. Threat Hunting

Use the accepted read-only hunt flow.

Show non-zero real results when available.

Message:

> The hunt builder produces read-only, bounded queries over persisted events. Analysts do not send arbitrary SQL to the database.

### 9. Case Operations

Show a prepared demo incident with visible tasks, handoffs and containment state.

Message:

> Case Operations demonstrates analyst workflow state. Presentation-only workflow data must remain separate from the immutable accepted Golden Demo evidence when that separation is required by the release contract.

### 10. AI Investigation

Show the repaired four-card AI status layout:

- Queue;
- Workers;
- Current job;
- Result UUID.

Then show an already persisted grounded result when available.

Message:

> The model is constrained to authorized evidence and governed knowledge. The answer is assistive. The persisted deterministic incident evidence remains authoritative.

### 11. Audit Trail

Show accountable actions and actor history.

Message:

> Security-sensitive actions and governed mutations are auditable.

### 12. System & AI Knowledge

Show:

- API READY;
- RAG READY;
- pgvector;
- accepted knowledge baseline;
- runtime administration.

Message:

> Operational readiness is independently testable; the AI layer is not a hidden black box.

## Two-minute compressed demo

For the **current enhanced v2** scenario, when time is limited:

1. Overview.
2. Current Analysis — show 29 / 26 / 2 / 0 for the selected v2 dataset.
3. Case Details — show persisted incident evidence.
4. Attack Graph or ATT&CK.
5. AI Investigation — explain evidence-first grounding.
6. System Health — show RAG/runtime readiness.

## Five interview questions you should answer confidently

### Why did you use PostgreSQL + pgvector?

Because the accepted architecture keeps durable SOC state and governed vector retrieval in PostgreSQL. pgvector provides vector similarity within the same durable database boundary instead of relying on the earlier historical SQLite vector-store prototype.

### Why Redis?

Redis is used as the asynchronous delivery queue for durable AI jobs. PostgreSQL remains the durable authority for job/application state, while Redis provides delivery to workers.

### Why two LLM profiles?

The platform supports a Standard profile using `qwen3.5:4b` and a Deep Analysis profile using `qwen3.5:9b`. The system can choose or accept an analysis mode while keeping grounding, authorization and evidence boundaries intact.

### How do you prevent hallucinations from becoming incident facts?

The LLM is downstream of persisted deterministic evidence. Retrieval is scoped, citations are validated, observed evidence is separated from governed knowledge, unsupported attribution is rejected or constrained, and fallback behavior is visible. AI output is not promoted to authoritative evidence merely because a model generated it.

### What happens if AI is unavailable?

The deterministic SOC architecture remains conceptually independent of AI availability. AI jobs can fail or degrade without redefining persisted incident facts. The runtime includes explicit health checks, queue/worker state and controlled fallback behavior.

## Deeper interview topics

Be ready to discuss:

- idempotent API behavior and the concurrency race that was repaired during hardening;
- PostgreSQL transaction/savepoint handling around idempotent AI-job creation;
- prompt-injection and secret-extraction testing;
- cross-incident RAG isolation;
- deterministic fallback;
- Docker health and controlled service recovery;
- observability and internal metrics exposure;
- account lockout and token rotation;
- branch/receipt/hash based release gates;
- non-destructive operational recovery;
- temporary supervised internet exposure versus permanent hosting.

See [Final Testing and Validation](FINAL_TESTING_AND_VALIDATION.md).

## What not to claim

Do not claim:

- that post-release changes on current `main` are part of the immutable v1.0.0 snapshot;
- that the LLM is the source of truth;
- that the system has zero vulnerabilities;
- that a threat-intelligence hit proves compromise;
- that the project is permanently hosted as a public production SOC;
- that historical exact test/API/rule counts are current unless re-derived;
- that the accepted 1007-chunk corpus count can never change.

## Presentation assets

The frozen presentation materials are under `presentation/`.

Useful files:

- [Demo Narrative](../presentation/DEMO_NARRATIVE.md)
- [Speaker Notes](../presentation/SPEAKER_NOTES.md)
- [Presentation README](../presentation/README_PRESENTATION.md)

## Demo safety checklist

Before a supervised demo:

- validate local runtime health;
- verify you are using the intended accepted branch/workflow;
- keep credentials private;
- never display `.env.batch7.local`;
- do not queue unnecessary new AI runs merely for screenshots;
- do not mutate the Golden Demo reference unless the current phase explicitly permits it;
- if a temporary internet tunnel is used, revoke it immediately after the demo.

## Final explanation to close an interview

> ThreatLens AI is an evidence-first SOC platform. Deterministic analytics and persisted evidence establish the security case; the RAG/LLM layer is a constrained investigation assistant over that authorized evidence. I focused not only on features but also on runtime reliability, security boundaries, adversarial AI testing, observability, concurrency correctness, auditable workflows and reproducible release gates.
