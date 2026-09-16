# ThreatLens AI Demo Narrative

ThreatLens AI is an evidence-first SOC investigation platform. Deterministic persisted evidence remains authoritative. AI operates downstream to retrieve, cite, summarize, and reason over persisted evidence.

## Golden Demo

Use reference analysis $ReferenceAnalysis and reference incident $ReferenceIncident.

Accepted deterministic flow:

- 10 normalized events
- 8 alerts
- 5 correlated incidents
- 0 quarantined records

Walk from Current Analysis through Incident Queue, Case Details, MITRE ATT&CK, Attack Graph, Threat Intelligence, and Threat Hunting.

## Case Operations

For Case Operations only, use the isolated presentation scenario:

- $demoTitle
- $demoIncident

It demonstrates real persisted workflow data:

- 3 tasks
- 1 handoff
- containment $(@{project=ThreatLens AI; phase=7D-R1; status=PASS; marker=PHASE7D-CASEOPS-DEMO-V1; target=; case_operations=; accepted_reference_analysis=93aa1e45-480d-4dbb-aae1-e4fd12db3c15; accepted_reference_incident=95275eea-92f9-498a-a975-74f53906e803; accepted_reference_preserved=True; mutation=NAMESPACED CASE-OPERATIONS DATA ON NON-REFERENCE BATCH-6 INCIDENT ONLY; source_git_cloudflare=UNCHANGED; evidence=D:\ThreatLensAI_Runtime\release_gates\phase7d_r1_caseops_demo_data_v2\20260917-014246}.case_operations.containment_status)

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

The AI Investigation summary UI was repaired on Phase7 without changing backend/RAG semantics.

## Audit and health

Finish with Audit Trail and System Health to show traceability, service readiness, observability, model readiness, and deployment boundaries.