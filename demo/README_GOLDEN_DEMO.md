# ThreatLens AI â€” Golden Demo Runbook

## Purpose

This is the recruiter/interviewer demonstration path for ThreatLens AI. It presents the accepted system as an evidence-first SOC platform: deterministic telemetry, detections, correlation, risk and evidence establish authoritative facts; investigation workflows, ATT&CK context, attack graphs, threat intelligence, hunting, case operations and grounded AI build on those persisted facts.

The Golden Demo is non-destructive. It uses the accepted read-only Phase-3/Phase-4 SOC evidence and does not reset PostgreSQL, Redis, Ollama models or the pgvector knowledge index.

## Start

From PowerShell in the repository root:

```powershell
.\START_THREATLENS_DEMO.ps1
```

For validation without opening a browser:

```powershell
.\START_THREATLENS_DEMO.ps1 -NoBrowser
```

The launcher validates Phase-5 source lineage, reuses an already-healthy runtime when possible, starts/reuses Compose services with `up -d --no-build` when necessary, requires full observability and AI/RAG readiness, resolves the stable demo context, prints deep links, and opens the Overview page.

Authentication and RBAC remain enabled. Sign in with an existing authorized ThreatLens analyst account. No username, password, PAT, token, ingest key or other credential is stored in the launcher or runbook.

## Locked SOC story

- Analysis UUID: `93aa1e45-480d-4dbb-aae1-e4fd12db3c15`
- Integrated incident UUID: `95275eea-92f9-498a-a975-74f53906e803`
- Incident: **Multi-Stage Credential Access Activity**
- Story: **10 normalized events â†’ 8 alerts â†’ 5 correlated incidents â†’ 0 quarantined records**
- The same accepted context contains case notes, evidence and custody history, attack-graph snapshots, threat-intelligence hits, saved hunt activity, grounded-RAG history and audit records.

## 12-step recruiter walkthrough

1. **Overview** â€” explain ThreatLens as an evidence-first SOC platform, not an LLM-first chatbot.
2. **Current Analysis** â€” show the accepted heterogeneous analysis and its 10 events / 8 alerts / 5 incidents.
3. **Incident Queue** â€” select the locked integrated incident and explain risk/prioritization.
4. **Case Details** â€” walk timeline, correlated alerts, entities and persisted evidence.
5. **MITRE ATT&CK** â€” show governed ATT&CK mappings as investigation context.
6. **Attack Graph** â€” show the correlation-run-backed attack graph and multi-stage story.
7. **Threat Intelligence** â€” show external enrichment while explaining it does not overwrite authoritative incident facts.
8. **Threat Hunting** â€” show saved hunting/execution capability around the evidence.
9. **Case Operations** â€” show notes, registered evidence, SHA-256 integrity and custody history.
10. **AI Investigation** â€” ask: `Summarize the persisted incident evidence, separate observed facts from inference, cite every factual assessment, and state limitations.` Explain grounding, citations and limitations.
11. **Audit Trail** â€” show traceability of analyst/security actions.
12. **System Health** â€” finish with PostgreSQL, Redis, API, worker, frontend, Prometheus/Grafana, Ollama and grounded-RAG readiness.

## Architecture message

ThreatLens keeps authoritative incident facts deterministic. Parsing, detections, correlations, risk, evidence and case state are persisted independently of AI. The RAG/LLM layer consumes persisted evidence, retrieves incident/knowledge context and produces structured grounded analysis with citations and limitations. AI output never becomes the authoritative incident record.

## Safety

Do not perform destructive cleanup before a demo. Do not alter accepted Phase-3/4 evidence to improve the story. Do not disable RBAC or the login boundary. Do not hard-code or expose credentials. Do not promise an exact LLM sentence, latency or relevance score; these are runtime-dependent. If live AI is slow, explain the architecture and use prior persisted grounded history only when clearly labeled as a previous result.

## Console URL

Primary entry point:

`http://127.0.0.1:8080`

The React console uses stable hash routes and carries the locked `analysis` and `incident` UUIDs in the URL. The launcher prints the direct Overview, Case, AI Investigation and System Health links.