# ThreatLens AI Demo Narrative

ThreatLens AI is an evidence-first SOC investigation platform. Deterministic persisted evidence remains authoritative. AI operates downstream to retrieve, cite, summarize, and reason over persisted evidence.

## Golden Demo

Use reference analysis `93aa1e45-480d-4dbb-aae1-e4fd12db3c15` and reference incident `95275eea-92f9-498a-a975-74f53906e803` (`Multi-Stage Credential Access Activity`).

Accepted deterministic flow:

- 10 normalized events
- 8 alerts
- 5 correlated incidents
- 0 quarantined records

Walk from Current Analysis through Incident Queue, Case Details, MITRE ATT&CK, Attack Graph, Threat Intelligence, and Threat Hunting.

## Case Operations

For Case Operations only, use the isolated presentation scenario:

- Marker: `PHASE7D-CASEOPS-DEMO-V1`
- Resolve the namespaced presentation incident from persisted runtime context; do not hard-code a numeric database ID.

It demonstrates real persisted workflow data:

- 3 tasks
- 1 handoff
- containment: `in_progress`

This is intentionally separate from the accepted Golden Demo incident.

## AI Investigation

Return to the accepted Golden Demo investigation for the AI story.

Explain:

- Queue and durable workers
- Standard model qwen3.5:4b
- Deep model qwen3.5:9b
- qwen3-embedding:0.6b
- pgvector retrieval
- 1007 indexed chunks
- evidence citations
- grounding and limitation handling
- deterministic persisted evidence remains authoritative

The AI Investigation summary UI was repaired during Phase 7 without changing backend/RAG semantics.

## Audit and health

Finish with Audit Trail and System Health to show traceability, service readiness, observability, model readiness, and deployment boundaries.