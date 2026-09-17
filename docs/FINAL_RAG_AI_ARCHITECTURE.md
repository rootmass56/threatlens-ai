# ThreatLens AI — Final RAG / AI Architecture

## Purpose

ThreatLens uses grounded generative AI to assist incident investigation **after** deterministic evidence has been persisted.

The AI subsystem is not the authority for whether an incident happened.

## Core invariant

```text
deterministic persisted evidence = authoritative
LLM output                       = assistive / downstream
```

Any final documentation, demo or interview explanation must preserve this distinction.

## Runtime components

### Standard generation

Model: `qwen3.5:4b`

Accepted runtime profile:

- context window: 4096;
- output-token budget: 768;
- read timeout: 300 seconds.

### Deep Analysis

Model: `qwen3.5:9b`

Accepted runtime profile:

- context window: 16384;
- output-token budget: 1600;
- read timeout: 600 seconds.

### Embeddings

Model: `qwen3-embedding:0.6b`

Embedding dimensions: **1024**.

### Vector backend

Accepted backend: **PostgreSQL + pgvector**.

The accepted release-gate runtime currently reports **1007 indexed chunks**. This count is an accepted evidence point, not an architectural constant.

## High-level flow

```text
Authenticated analyst
       |
       v
incident-scoped question
       |
       v
scope / authorization / security checks
       |
       +--------------------+
       |                    |
       v                    v
persisted incident      governed knowledge
evidence context        retrieval
       |                    |
       +---------+----------+
                 |
                 v
        bounded grounded prompt
                 |
       +---------+----------+
       |                    |
       v                    v
    Standard              Deep
  qwen3.5:4b          qwen3.5:9b
       |                    |
       +---------+----------+
                 |
                 v
      structured generation
                 |
                 v
 citation / grounding validation
                 |
                 v
 persisted answer + metadata + audit
```

## Context separation

ThreatLens separates:

1. observed incident evidence;
2. governed knowledge;
3. analyst/AI inference.

A knowledge document that says a technique *can* represent credential access must not be rewritten as if credential access was observed in the current incident unless persisted incident evidence supports that statement.

## Incident isolation

RAG queries are scoped to authorized incident context. Named or accidental cross-incident data must not be silently pulled into another incident's answer.

## Prompt-injection posture

Retrieved text, notes and telemetry are data, not instructions.

The project includes controls and adversarial acceptance tests around prompt injection, secret extraction, unsupported attribution, citation spoofing and overclaiming.

## Citations

The assistant should cite the authorized context used for factual claims.

ThreatLens distinguishes incident-evidence citations from governed-knowledge citations. This allows an analyst to see whether a statement came from what was observed versus what is general security knowledge.

## Routing

Analysts can request Auto, Standard or Deep Analysis.

Auto routing is deterministic. An LLM does not autonomously decide which LLM should be trusted as an authority.

## Failure handling

AI failure must not make deterministic SOC analytics unavailable.

The accepted architecture supports controlled fallback behavior. Depending on the failure and request, an eligible Deep request can fall back toward Standard processing, and deterministic grounded degradation can preserve an evidence-based result when live model generation is unavailable.

Fallback must be visible in result metadata rather than silently presented as a full live-model answer.

## Durable jobs

AI investigations are durable asynchronous jobs:

```text
FastAPI
  |
  v
PostgreSQL job metadata
  |
  v
Redis delivery queue
  |
  v
worker
  |
  v
generation / validation
  |
  v
persisted result
```

The runtime bounds active jobs globally and per actor.

The platform's authority remains the persisted deterministic incident evidence even when the AI queue is slow or unavailable.

## Observability

The AI subsystem is covered by:

- service health;
- worker registration;
- Redis reachability;
- queue state;
- RAG runtime readiness;
- embedding reachability;
- model availability;
- retrieval smoke;
- structured-generation smoke.

Use:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

for strict accepted-runtime validation.

## What to say in a demo/interview

A precise explanation is:

> ThreatLens uses deterministic analytics and persisted evidence as the source of truth. The RAG layer retrieves only authorized incident evidence plus governed security knowledge, then uses local Qwen generation with citation and grounding controls. AI can explain the case, but it does not create the authoritative incident facts.

Do not describe the system as an autonomous AI SOC that decides what happened without deterministic evidence.
