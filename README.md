# ThreatLens AI v0.14.0

> **Released as `v1.0.0`** — production-style, evidence-first SOC investigation platform with deterministic detections, incident correlation, MITRE ATT&CK context, attack graphs, threat intelligence, threat hunting, auditable case operations, and grounded RAG/LLM investigations.

[Public showcase](https://threatlens-ai-showcase.pages.dev) · [Architecture](docs/FINAL_ARCHITECTURE.md) · [Feature guide](docs/FINAL_FEATURE_GUIDE.md) · [Demo & interview guide](docs/FINAL_DEMO_AND_INTERVIEW_GUIDE.md) · [Security model](docs/FINAL_SECURITY_MODEL.md) · [Release tag](../../releases/tag/v1.0.0)

## Why ThreatLens AI

ThreatLens AI is built around one rule: **deterministic persisted evidence remains authoritative; AI stays downstream of evidence**. The platform ingests heterogeneous security telemetry, normalizes it, evaluates governed detections, correlates alerts into incidents, preserves case evidence and audit history, maps activity to MITRE ATT&CK, builds persisted attack graphs, supports threat intelligence and hunting workflows, and then uses grounded AI to explain the evidence with citations.

The AI layer does not establish incident facts. It consumes authorized persisted evidence and governed knowledge, validates citations after generation, and exposes explicit fallback and grounding behavior.

## Golden Demo — Verified End-to-End Investigation

> **Deterministic release-acceptance fixture—not a scale benchmark.** The frozen Golden Demo is a reproducible, multi-source dataset with known outcomes. These values describe that fixture, not lifetime platform totals or maximum throughput.

| **10**<br>Normalized events | **8**<br>Deterministic alerts | **5**<br>Correlated incidents | **0**<br>Quarantined records |
| :---: | :---: | :---: | :---: |
| Telemetry parsed and persisted | Governed rules produced evidence | Alerts grouped into durable investigations | Every record in the valid fixture followed the accepted path |

**Evidence path**

`Telemetry` → `Normalization` → `Detections` → `Alerts` → `Correlation` → `Incidents` → `Case evidence` → `ATT&CK + attack graph` → `Threat intelligence + hunting` → `Grounded AI` → `Audit trail`

**What this proves**

- Deterministic evidence and incident state exist before any LLM is invoked.
- The same persisted investigation continues through case evidence, ATT&CK context, attack graphs, threat-intelligence enrichment, bounded hunting, grounded AI and audit history.
- AI operates only on authorized evidence and governed knowledge, with post-generation citation validation and explicit fallback behavior.
- Malformed and invalid inputs were tested separately against quarantine/error contracts; the `0` above describes the accepted valid fixture, not the absence of quarantine controls.

Reproduce the presentation workflow with `.\START_THREATLENS_DEMO.ps1`.

[Golden Demo contract](demo/README_GOLDEN_DEMO.md) · [Validation evidence](docs/FINAL_TESTING_AND_VALIDATION.md) · [Recruiter walkthrough](docs/FINAL_DEMO_AND_INTERVIEW_GUIDE.md)

## Core capabilities

- Multi-source security telemetry ingestion and normalization
- Deterministic detection engine, risk scoring and governed rule catalog
- Alert-to-incident correlation and persisted attack graph investigation
- MITRE ATT&CK catalog and rule/evidence mappings
- Threat-intelligence feeds, normalized indicators and enrichment hits
- Read-only structured threat hunting across persisted events
- Evidence-backed case operations, notes, custody and analyst handoffs
- Durable asynchronous AI investigation jobs through PostgreSQL + Redis workers
- Grounded RAG with pgvector retrieval, citation validation and cross-incident isolation
- Adaptive Standard/Deep local Qwen model profiles with deterministic fallback
- RBAC-protected FastAPI API and React SOC console
- Prometheus/Grafana observability and exporter health
- DevSecOps CI with Pytest, Ruff, frontend checks, dependency audit, secret scanning, Trivy and CodeQL

## Architecture

```text
Telemetry sources
      │
      ▼
Ingestion / normalization
      │
      ▼
Deterministic detections ──► alerts ──► correlation ──► incidents
      │                                            │
      │                                            ├─► case evidence / custody / audit
      │                                            ├─► MITRE ATT&CK
      │                                            ├─► persisted attack graph
      │                                            ├─► threat intelligence / hunting
      │                                            └─► authorized evidence context
      │                                                        │
      └────────────────────────────────────────────────────────▼
                                              pgvector retrieval + grounded RAG
                                                        │
                                                        ▼
                                               cited AI investigation
```

Detailed architecture: [`docs/FINAL_ARCHITECTURE.md`](docs/FINAL_ARCHITECTURE.md)

## Technology stack

**Backend:** Python, FastAPI, SQLAlchemy, Alembic, PostgreSQL, pgvector, Redis  
**Frontend:** React, TypeScript, Vite, Nginx  
**AI/RAG:** Ollama, Qwen3.5 Standard/Deep profiles, Qwen3 embedding, pgvector  
**Security/SOC:** MITRE ATT&CK, deterministic detection/correlation, threat hunting, threat intelligence, case/evidence workflows  
**Operations:** Docker Compose, Prometheus, Grafana, PostgreSQL/Redis exporters  
**DevSecOps:** GitHub Actions, Pytest, Ruff, CodeQL, Gitleaks, Trivy, dependency audit, SBOM

## Local production-style runtime

Prerequisites: Docker Desktop / Docker Engine, PowerShell, and the required local Ollama models documented in the deployment guide.

```powershell
Copy-Item .env.example .env.batch7.local
# Configure local secrets in .env.batch7.local; never commit it.

.\START_THREATLENS.ps1
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

SOC console: `http://127.0.0.1:8080`

For the deterministic presentation workflow:

```powershell
.\START_THREATLENS_DEMO.ps1
```

Deployment and operations: [`docs/FINAL_DEPLOYMENT_AND_OPERATIONS.md`](docs/FINAL_DEPLOYMENT_AND_OPERATIONS.md)

## Grounded AI contract

The accepted runtime uses:

- **Standard:** `qwen3.5:4b`
- **Deep Analysis:** `qwen3.5:9b`
- **Embedding:** `qwen3-embedding:0.6b`
- **Vector backend:** pgvector
- **Accepted knowledge baseline:** 1007 indexed chunks

Grounded responses are constrained by authorized evidence, governed knowledge and post-generation citation validation. Unsupported attribution, cross-incident leakage, prompt-injection behavior and fallback paths were explicitly tested during release hardening.

See [`docs/FINAL_RAG_AI_ARCHITECTURE.md`](docs/FINAL_RAG_AI_ARCHITECTURE.md).

## Security model

ThreatLens keeps deterministic evidence, external threat intelligence, analyst inference and AI-generated interpretation conceptually separate. Authentication, RBAC, auditability, secret boundaries, input validation, job concurrency controls and AI grounding protections are part of the final security model.

See [`SECURITY.md`](SECURITY.md) and [`docs/FINAL_SECURITY_MODEL.md`](docs/FINAL_SECURITY_MODEL.md).

## Validation and release

The final `v1.0.0` release was merged through the protected `main` workflow after the required CI and CodeQL checks passed. The accepted release includes runtime/RAG health validation, adversarial AI/RAG checks, controlled infrastructure recovery, concurrency/idempotency repair, performance testing, end-to-end SOC UAT, presentation assets and final documentation acceptance.

Release history is retained in Git tags and repository history; current users should start with the final documentation rather than historical batch artifacts.

## Documentation

| Purpose | Document |
| --- | --- |
| Architecture | [`FINAL_ARCHITECTURE.md`](docs/FINAL_ARCHITECTURE.md) |
| Deployment & operations | [`FINAL_DEPLOYMENT_AND_OPERATIONS.md`](docs/FINAL_DEPLOYMENT_AND_OPERATIONS.md) |
| Security | [`FINAL_SECURITY_MODEL.md`](docs/FINAL_SECURITY_MODEL.md) |
| RAG / AI architecture | [`FINAL_RAG_AI_ARCHITECTURE.md`](docs/FINAL_RAG_AI_ARCHITECTURE.md) |
| Testing & validation | [`FINAL_TESTING_AND_VALIDATION.md`](docs/FINAL_TESTING_AND_VALIDATION.md) |
| Feature guide | [`FINAL_FEATURE_GUIDE.md`](docs/FINAL_FEATURE_GUIDE.md) |
| Demo / interview walkthrough | [`FINAL_DEMO_AND_INTERVIEW_GUIDE.md`](docs/FINAL_DEMO_AND_INTERVIEW_GUIDE.md) |
| Troubleshooting | [`FINAL_TROUBLESHOOTING.md`](docs/FINAL_TROUBLESHOOTING.md) |
| Known limitations | [`FINAL_LIMITATIONS.md`](docs/FINAL_LIMITATIONS.md) |
| Presentation assets | [`presentation/README_PRESENTATION.md`](presentation/README_PRESENTATION.md) |

## Release lineage

- **v1.0.0** — final protected release of the evidence-first SOC platform.
- **v0.10.0 Grounded RAG Investigation Assistant** — historical milestone retained as part of the release lineage and regression contract for the grounded investigation capability.

The internal source lineage remains `0.14.0` for compatibility with the accepted runtime/version contract; the published project release is `v1.0.0`.

## Responsible use

ThreatLens AI is an educational and defensive security engineering project. Use it only with systems, telemetry and environments you are authorized to assess. AI output is investigative assistance, not independent proof of compromise.
