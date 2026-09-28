# ThreatLens AI — Enhanced Golden Demo v2

Enhanced v2 is the final portfolio scenario. It complements—but never changes—the immutable v1.0.0 accepted demo.

The scenario follows one synthetic intrusion across Microsoft Entra ID, Windows Security, Sysmon, Suricata and Zeek. It is generated from raw source fixtures, processed by the production connector/rule/correlation path, persisted transactionally, enriched through governed SOC services, and finished with a grounded AI investigation.

## Locked result

| Signal | Accepted v2 result |
|---|---:|
| Raw/normalized events | 29 |
| Deterministic alerts | 26 |
| Representative alerts after correlation deduplication | 23 |
| Correlated incidents | 2 critical |
| Quarantined records | 0 |
| Parse success | 100% |
| Telemetry connectors | 5 |
| ATT&CK tactics | 8 |
| ATT&CK techniques | 19 |
| Resolved entities | 21 |
| Scored relationships | 139 |
| Attack-graph nodes / edges | 76 / 300 |

The two incidents are intentionally linked parts of the same investigation:

1. **Credential Attack with Suspicious Execution** — identity compromise, privilege escalation, encoded PowerShell, credential access, injection, RDP lateral movement, payload transfer, persistence and C2.
2. **Multi-Stage Defense Impairment Activity** — DNS tunneling, suspicious TLS, sensitive-file deletion and Windows audit-log clearing.

## Start the final demo

From an accepted Windows runtime/worktree:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo\start-enhanced-demo-v2.ps1
```

For a non-browser verification:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo\start-enhanced-demo-v2.ps1 -NoBrowser -ContextOut .\enhanced-v2-context.json
```

The launcher:

1. verifies the worktree descends from the protected post-v1.0.0 foundation;
2. starts or reuses the existing Compose runtime without reset or rebuild;
3. requires database, frontend, observability, Ollama and RAG health;
4. seeds v2 through the actual application and SOC service interfaces;
5. runs the grounded deep-analysis query;
6. rejects any deterministic or capability drift;
7. opens the authenticated console with the analysis and primary incident selected.

Re-running the launcher is safe. The analysis fingerprint and namespaced operational lookups prevent duplicate v2 records.

## Investigation timeline

| UTC | Evidence | Deterministic interpretation |
|---|---|---|
| 08:00–08:03 | Repeated MFA failures followed by a high-risk successful Entra sign-in from `203.0.113.77` | Credential attack and risky cloud-account access |
| 08:08 | The same identity assigns a privileged cloud role | Cloud privilege escalation |
| 08:12–08:19 | Five Windows logon failures, explicit credentials and special privileges on `FIN-WS-042` | Brute force/credential use followed by privileged access |
| 08:21–08:26 | Encoded PowerShell, LSASS access and remote-thread creation | Execution, credential dumping and process injection |
| 08:31–08:35 | PowerShell initiates RDP, followed by a Suricata C2 alert | Lateral movement and command-and-control |
| 08:42–08:48 | New account, Domain Admin membership, scheduled task and Run-key change | Account manipulation and redundant persistence |
| 08:55–09:04 | Suspicious POST, DNS tunneling, long DNS query and suspicious TLS SNI | C2/exfiltration-like network activity |
| 09:10–09:12 | SAM deletion followed by Security-log clearing | Evidence destruction and defense impairment |

## What is fact, enrichment and AI

- **Observed fact:** the normalized events and their immutable source records.
- **Deterministic conclusion:** governed YAML detections, risk scores, deduplication, correlation, incident stages and attack graph.
- **External enrichment:** curated IOC matches with provenance and an explicit `enrichment_only` boundary.
- **Analyst action:** note, P1 workflow, evidence registration, verified chain of custody, saved hunt, task and true-positive feedback.
- **Response record:** a separately approved endpoint-isolation simulation. No autonomous containment occurs.
- **AI output:** a downstream explanation that must cite persisted evidence/knowledge, expose uncertainty and never create authoritative facts.

## Recommended 12-step interview walkthrough

1. **Overview** — establish the 29 / 26 / 2 / 0 contract and the evidence-first architecture.
2. **Current Analysis** — show five source manifests, 100% parsing and zero quarantine.
3. **Incident Queue** — show both P1 critical incidents and explain why correlation split the late defense-impairment cluster.
4. **Case Details** — inspect the primary incident’s ordered storyline, contributing alerts and supporting events.
5. **MITRE ATT&CK** — show 19 techniques across the intrusion lifecycle.
6. **Attack Graph** — pivot among the identity, endpoint, internal/external IPs, processes, files, URLs and domains.
7. **Threat Intelligence** — show that IOC matches are provenance-preserving enrichment, not fact creation.
8. **Threat Hunting** — execute/review the saved `198.51.100.88` infrastructure pivot.
9. **Case Operations** — show ownership, P1 task, evidence SHA-256 and verified custody event.
10. **Response** — show request → approval → simulated completion and the no-autonomous-destruction policy.
11. **AI Investigation** — ask the locked v2 question; verify citations, grounding and uncertainty language.
12. **Audit/System Health** — finish with the append-only action trail and healthy production-style stack.

## Locked AI question

> Using only persisted evidence and cited governed knowledge, explain the attack progression, highest-confidence findings, containment priorities, and important uncertainties. Do not convert threat-intelligence context into observed facts.

## Verification commands

```bash
python scripts/enhanced_demo_v2.py seed
python scripts/enhanced_demo_v2.py verify
pytest -q tests/test_enhanced_demo_v2.py
```

The launcher uses `seed --with-rag` and therefore applies the stricter final readiness gate.

## Non-negotiable boundary

The accepted v1 demo (`10 / 8 / 5 / 0`) and the `v1.0.0` tag remain immutable. Enhanced v2 is a separately namespaced post-release portfolio scenario.
