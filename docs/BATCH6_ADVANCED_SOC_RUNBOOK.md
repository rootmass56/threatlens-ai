# ThreatLens AI v0.13 — Batch 6 Advanced SOC Runbook

## Scope
Batch 6 expands the frozen Batch-5 production foundation without weakening its evidence-first security model.

- **6A Real-time ingestion:** authenticated HTTP ingestion, durable receipt ledger, idempotency, source CIDR/rate controls, optional UDP syslog edge collector.
- **6B Threat intelligence:** curated/STIX indicator ingestion, provenance, confidence/TLP/validity, IOC enrichment kept separate from observed evidence.
- **6C Threat hunting:** structured read-only grammar, saved hunts and execution history; no arbitrary analyst SQL.
- **6D Case operations:** team/owner/SLA profile, tasks, handoffs and evidence chain-of-custody events.
- **6E Response playbooks:** explicit request → approval → externally executed/simulated completion. ThreatLens does not autonomously perform destructive containment.
- **6F Detection feedback:** TP/FP feedback, effectiveness metrics and governed tuning proposals. Approved proposals do not silently mutate runtime YAML rules.
- **6G Cloud/identity:** Microsoft Entra sign-in/audit normalization plus governed risky sign-in, MFA-failure, failed-sign-in and privileged-role detections.
- **6H Graph/search:** evidence-backed graph summaries/path explanations, entity timeline and global investigation search.

## Local start
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\bootstrap_batch6_env.ps1
.\scripts\start_batch6_stack.ps1
.\scripts\verify_batch6_live.ps1
```
Open `http://127.0.0.1:8080`.

## Syslog
Create a `syslog_rfc` ingestion source in the Real-Time Ingestion page/API. Copy the one-time key into `THREATLENS_SYSLOG_INGEST_KEY` in `.env.batch6.local`, then run `scripts\start_batch6_syslog.ps1`. UDP/5514 is not started by default.

## Security boundaries
1. Browser/API analyst operations use JWT + RBAC.
2. Machine ingestion uses a source-specific one-time API key in `X-ThreatLens-Ingest-Key`; only its SHA-256 hash is persisted.
3. Realtime receipt is committed before parse/detection processing.
4. Threat-intelligence hits are enrichment, never deterministic proof of compromise.
5. Hunt grammar is field-constrained and read-only.
6. Response actions require approval; completion records simulation/external execution evidence.
7. Detection tuning remains governance data until a versioned YAML+fixture change is separately approved.

## Freeze criteria
Do not tag Batch 6 frozen until migrations, 46-rule/138-fixture governance, 6A–6H API/RBAC, frontend typecheck/build, Docker health, browser UAT, Batch-5 durable AI regressions and security regressions pass in the target Windows/Docker/Ollama environment.
