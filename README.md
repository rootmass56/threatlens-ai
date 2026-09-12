# ThreatLens AI v0.14.0 — Batch 7 Operational Hardening

> **Current package:** Batch-7 operational-hardening release candidate built directly on the frozen v0.13.0 / Batch-6 SOC capability boundary. v0.13.0 remains immutable; Batch 7 adds observability, measured performance/concurrency tooling, database performance indexes, backup/restore/DR, container/API hardening, DevSecOps, CI/CD and operational runbooks. Run every Batch-7 acceptance gate before freezing v0.14.0.

## Batch 7 phases

- **7A Observability:** structured JSON API/worker logs, request correlation, internal Prometheus metrics, PostgreSQL/Redis exporters and provisioned Grafana dashboard.
- **7B Performance & concurrency:** bounded repeatable load probes with measured success rate, throughput and p50/p95/p99 latency.
- **7C PostgreSQL/pgvector performance:** operational composite-index migration and PostgreSQL statistics audit.
- **7D Backup/restore/DR:** SHA-256-manifested PostgreSQL backups, isolated restore smoke and guarded approved restore.
- **7E Security hardening:** request body ceiling, conditional HSTS, stronger browser headers, non-root/no-new-privileges/capability-drop container posture and static security audit.
- **7F DevSecOps:** reviewed dependency contract, v0.14 CycloneDX SBOM, secret/dependency/container scans and CodeQL workflow.
- **7G CI/CD:** PR/push gates plus manual immutable GHCR image publication by Git SHA. Final cloud deployment remains Batch 8.
- **7H Operations/freeze:** outage, recovery, backup, credential, deployment and security-incident runbooks plus final v0.14 release gate.

## Operational entrypoints

- `scripts/bootstrap_batch7_env.ps1`
- `scripts/MIGRATE_BATCH6_DATA_TO_BATCH7.ps1`
- `scripts/start_batch7_stack.ps1 -Observability`
- `scripts/verify_batch7_static.ps1`
- `scripts/verify_batch7_live.ps1`
- `scripts/backup_batch7.ps1`
- `scripts/restore_batch7_smoke.ps1`
- `BATCH7_ACCEPTANCE_CHECKLIST.md`

The Batch-7 Docker profile keeps PostgreSQL/Redis private, binds the local web/observability surfaces to loopback, and intentionally keeps `/internal/metrics` outside the Nginx `/api/` proxy. Final public HTTPS/cloud architecture is a separate Batch-8 acceptance boundary.

---

## Frozen Batch 6 capability baseline retained

Batch 7 preserves the full v0.13.0 capability set: authenticated realtime ingestion, threat intelligence, threat hunting, advanced case operations/evidence custody, approval-gated response, governed detection tuning, Microsoft Entra ID telemetry, graph intelligence/global search, and durable PostgreSQL+Redis grounded AI jobs.

# ThreatLens AI v0.12.0

ThreatLens AI is an evidence-first Security Operations Center (SOC) analytics and incident-investigation platform. It ingests heterogeneous security telemetry, normalizes events into a common schema, evaluates governed deterministic detections, maps evidence to MITRE ATT&CK, correlates alerts into explainable incidents and attack graphs, persists auditable case state, and exposes the platform through an authenticated FastAPI boundary and role-aware analyst UI.

## v0.12.0 Production Web Platform

v0.12.0 extends the immutable v0.11.1 baseline into a deployable SOC web platform. The production topology is React/Vite on Vercel, Dockerized FastAPI on Render, managed PostgreSQL for SOC persistence, pgvector for governed RAG vectors, and an authenticated HTTPS Ollama-compatible inference service. Local development continues to support SQLite and local Ollama.

Default v0.12 generation profiles are `qwen3.5:4b` (Standard) and `qwen3.5:9b` (Deep); `qwen3-embedding:0.6b` remains the 1024-dimensional embedding model. Model and inference endpoint values are environment-controlled and remain subject to the same grounding, citation, fallback and audit controls.

### Feature-parity release candidate

The production React console now governs the complete analyst-facing surface that previously existed only in the local Streamlit UI: telemetry upload, current/history analysis, incident workflow and evidence, attack-graph investigation, audit, detection quality and fixtures, ATT&CK coverage/Navigator, connector diagnostics, reporting, RAG administration and security/user administration. `config/frontend_feature_parity_v0.12.json` and `python -m scripts.verify_frontend_feature_parity` make that parity an explicit release gate.

For upgrades from a local v0.11.1 working database, `MIGRATE_V0111_DATA_TO_V012.ps1` performs a guarded operational-data migration into the v0.12 SQLite UAT database. It preserves the v0.12 security identity (users, roles, password hashes, refresh tokens and login-attempt state) and creates a target backup before an applied migration. See `docs/DATA_MIGRATION_v0.11.1_to_v0.12.md`.

The expanded governed Windows target is **271 tests**: 270 platform-independent tests plus the exact Windows/Python 3.11 runtime-pin test. The release remains an RC until that complete gate, local feature-parity UAT, PostgreSQL/pgvector staging, production inference, Render/Vercel deployment and live UAT all pass.

See `docs/PROJECT_STATUS_v0.12.0.md`, `docs/LLM_STRATEGY_v0.12.0.md` and `docs/DEPLOYMENT_v0.12.0.md`.

## v0.11.1 Security Closure

v0.11.1 is a security/release-hardening patch over the verified v0.11 adaptive AI runtime. It closes the final frozen-release audit findings without changing ThreatLens's authority model:

- upgrades `python-multipart` to `0.0.32`;
- upgrades `requests` to `2.34.2`;
- upgrades `pytest` to `9.0.3`;
- removes ChromaDB and its network-capable dependency surface completely;
- replaces Chroma with a ThreatLens-owned persistent `sqlite3` vector store using exact cosine retrieval over the governed corpus;
- adds an offline reviewed dependency-security baseline;
- adds exact installed transitive dependency lock + CycloneDX runtime SBOM generation on the supported Windows/Python 3.11 environment;
- adds an immutable source dependency CycloneDX inventory;
- corrects v0.11 verification counts, release documentation and runtime configuration references;
- retains adaptive 4B/8B routing, technique-bound citations, conservative claim hardening and deterministic degraded fallback.

The v0.11.1 vector backend intentionally uses the Python standard library rather than a separately served vector database. At the current governed corpus size (about one thousand chunks), an exact cosine scan is deterministic, simple to audit, and removes an unnecessary vulnerable server dependency.

> **Upgrade note:** existing v0.10/v0.11 Chroma index files are not reused. Preserve the database and ATT&CK catalog, then run `python -m scripts.index_rag_knowledge --force` once to build `data/rag/vector_store.sqlite3` with the existing Qwen embedding model.

## v0.10.0 Grounded RAG Investigation Assistant

v0.10 established the incident-scoped evidence/knowledge trust boundary retained by v0.11.1: deterministic detections and persisted evidence remain authoritative, while local generative models may only explain authorized incident evidence and governed security knowledge through validated citations.

## Adaptive grounded AI runtime

Analysts choose **Auto**, **Standard**, or **Deep Analysis**. Auto routing is deterministic; an LLM never chooses which LLM to invoke. v0.12 upgrades the generation profiles while retaining the evidence-first trust boundary.

```text
Analyst question
      |
security/scope checks + deterministic query plan
      |
Auto / Standard / Deep routing
      |
  +---+---------------------+
  |                         |
Standard                   Deep Analysis
Qwen3.5:4B                 Qwen3.5:9B
8192 ctx / 900 output      16384 ctx / 1600 output
120 s read timeout         600 s read timeout
  |                         |
  +------------+------------+
               |
       same incident evidence
       same governed knowledge
       same citation validation
       same grounding/security controls
               |
       model failure handling
               |
   Standard fallback or deterministic
   evidence-only grounded degradation
```

Key controls:

- deterministic query-complexity routing with explicit analyst override;
- Standard `qwen3.5:4b` and Deep `qwen3.5:9b` profiles;
- transparent Deep-to-Standard fallback for eligible Deep failures;
- guarded deterministic evidence-only fallback after local-model failure;
- requested/resolved mode, requested/served model, fallback state, reasons and generation latency persisted in assistant history/audit metadata;
- prompt-injection, unsupported-attribution, named cross-incident and missing-specific-fact refusals before model invocation;
- deterministic ATT&CK technique deduplication and technique-specific knowledge-citation binding;
- internal prompt citation aliases removed from analyst-facing prose;
- bounded analyst-inference presentation and conservative handling of compromise/credential-theft/lateral-movement claims.

## Evidence-first RAG trust boundary

Deterministic detections, incident scoring, ATT&CK mappings, correlations and persisted case evidence remain authoritative. AI explains authorized evidence; it does not establish that an attack occurred.

```text
Persisted incident evidence                Governed security knowledge
alerts / events / entities                 ThreatLens docs / rules / ATT&CK
relationships / evidence / notes          allowlisted + versioned + hashed
            \                                  /
             \                                /
              -> bounded server context + retrieval
                         |
                         v
              Standard / Deep local Qwen
                         |
                         v
          structured answer + validated citations
          + grounding status + limitations + audit
```

Grounded-RAG controls include:

- incident context compiled server-side after authentication/authorization;
- Streamlit uses the FastAPI boundary and never talks directly to Ollama or vector storage;
- approved knowledge sources are allowlisted and SHA-256 versioned;
- deterministic chunk identities and hash-based incremental indexing;
- retrieved text, analyst notes and telemetry treated as untrusted data, never instructions;
- prompt-injection/secret-extraction patterns rejected before generation;
- citation IDs validated against the exact authorized context;
- incident-evidence and governed-knowledge citation planes enforced separately;
- exact ATT&CK/rule source lookup combined with semantic vector retrieval;
- attribution requires direct persisted evidence;
- every assistant query is persisted and creates an incident audit event;
- `rag:query` and `rag:manage` preserve the six-role RBAC model.

## Local and production vector storage

The v0.12 local RAG persistence retains `rag.vector_store.SQLiteVectorStore` using Python's built-in `sqlite3` module and deterministic exact-cosine retrieval. Production can switch to the native PostgreSQL/pgvector backend without changing the governed RAG model. Embeddings use the Ollama-compatible `/api/embed` boundary; generation uses `/api/chat` structured output.

Current v0.12 local defaults:

```text
Standard:   qwen3.5:4b
Deep:       qwen3.5:9b
Embeddings: qwen3-embedding:0.6b
Vector DB:  ThreatLens SQLite exact-cosine store
Production: PostgreSQL + pgvector
```

The runtime store defaults to:

```text
data/rag/vector_store.sqlite3
```

`data/rag/` is runtime state and is excluded from Git and immutable source releases.

## Deterministic platform

```text
Telemetry upload
  -> validation / connector selection
  -> Linux / Windows / Sysmon / Suricata / Zeek parsing
  -> Common Event Schema
  -> 42 governed YAML detection rules
  -> allowlisting / suppression / profiles
  -> alert severity, confidence and risk
  -> evidence-backed MITRE ATT&CK mappings
  -> semantic deduplication
  -> entity resolution
  -> explainable relationship scoring
  -> multi-stage / multi-source incident correlation
  -> persistent attack graph
  -> SQLAlchemy / Alembic persistence
  -> case workflow / notes / evidence / audit
  -> authenticated FastAPI
  -> six-role RBAC analyst interface
```

Validated deterministic baselines:

| Dataset | Events | Alerts | Incidents | Quarantined |
|---|---:|---:|---:|---:|
| Linux authentication | 9 | 4 | 1 | 0 |
| Five-source scenario | 22 | 8 | 2 | 0 |

The governed detection catalogue remains 42 enabled rules with 126 positive/negative/boundary fixtures. Advanced five-source correlation remains 8 input alerts, 7 representative alerts, 1 semantic duplicate, 10 resolved entities, 15 scored relationships, 2 incidents and a deterministic 30-node/62-edge graph.

## MITRE ATT&CK

ThreatLens retains pinned ATT&CK v19.1 awareness for Enterprise, Mobile and ICS. Catalog awareness is intentionally distinguished from evidence-backed detection coverage. Downloaded STIX bundles are runtime material and are excluded from immutable source ZIPs.

Governed RAG knowledge includes ThreatLens security/detection documentation, all governed detection rules, and active persisted Enterprise ATT&CK techniques after catalog synchronization.

## API

Authenticated RAG routes include:

```text
GET  /api/v1/rag/health
GET  /api/v1/rag/knowledge/status
POST /api/v1/rag/knowledge/reindex
POST /api/v1/incidents/{incident_uuid}/assistant/query
GET  /api/v1/incidents/{incident_uuid}/assistant/history
```

The canonical v0.12.0 OpenAPI contract remains **44 paths / 45 operations**. Development Swagger/ReDoc is disabled by default; administrators retain protected OpenAPI access through the security API.

## Persistence

Current Alembic head:

```text
d4a7c0e51010
```

The v0.12 schema currently remains at Alembic head `d4a7c0e51010`; production PostgreSQL uses the same ORM/migration contract. The model never receives arbitrary database access.

## Windows / CPython 3.11 setup

Prerequisites:

- Windows 10/11;
- CPython 3.11;
- PowerShell;
- Internet access for Python dependencies and first ATT&CK/model synchronization;
- Ollama for live AI generation and embeddings.

```powershell
cd D:\projects\ThreatLensAI
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\setup.ps1
```

Setup:

1. installs exact reviewed direct Python pins;
2. runs `pip check`;
3. verifies the reviewed dependency-security baseline and absence of ChromaDB;
4. captures the installed recursive dependency closure into `data/dependency_attestation/requirements-lock-windows-py311.txt`;
5. emits `data/dependency_attestation/cyclonedx-runtime-windows-py311.json` and an attestation digest;
6. upgrades Alembic and bootstraps security;
7. synchronizes pinned ATT&CK v19.1 catalogs unless skipped;
8. pulls configured Qwen models and builds the governed SQLite vector index when Ollama is available.

Runtime dependency-attestation files are machine-specific and excluded from immutable source releases; the source release includes `sbom/source-dependencies-v0.12.0.cdx.json` for its reviewed direct dependency contract.

Optional setup controls:

```powershell
$env:THREATLENS_SKIP_ATTACK_SYNC = "1"
$env:THREATLENS_SKIP_RAG_SETUP = "1"
$env:THREATLENS_SKIP_RAG_MODEL_PULL = "1"
```

For a v0.12 local runtime, use the v0.12 model variables from `.env.example` and rebuild the governed index if needed:

```powershell
$env:THREATLENS_RAG_STANDARD_LLM_MODEL = "qwen3.5:4b"
$env:THREATLENS_RAG_DEEP_LLM_MODEL = "qwen3.5:9b"
$env:THREATLENS_RAG_EMBEDDING_MODEL = "qwen3-embedding:0.6b"
python -m scripts.index_rag_knowledge --force
python -m scripts.verify_rag_runtime --require-ready
```

Historical `apply_v011_*` helpers are retained only as earlier-release evidence and are not part of the v0.12 operational path.

## Run the v0.12 React console locally

After the full installer/verification gate passes:

```powershell
.\RUN_THREATLENS_V012_UAT.ps1
```

The runner probes a safe loopback FastAPI port and serves the React/Vite console explicitly on `127.0.0.1:5173`. The bundled Streamlit UI under `app/` remains loopback-only historical/regression/reference code and is **not required by the production React deployment**.

Deterministic analytics remain available even if the external Ollama runtime is unavailable. The assistant reports degraded/unavailable state without affecting incident analytics.

## Verification

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
$env:THREATLENS_REQUIRE_RAG_READY = "1"
.\scripts\verify.ps1
```

The governed Windows v0.12 feature-parity matrix targets **271 tests**:

- 49 core/multi-source tests;
- 23 v0.4-v0.8 regressions;
- 101 v0.9-v0.9.5 security/UAT/release regressions;
- 32 v0.10 grounded/hybrid RAG tests;
- 28 v0.11 adaptive/runtime-hardening regressions;
- 12 v0.11.1 security-closure/vector/dependency regressions;
- 25 v0.12 production-web + React feature-parity/data-migration tests;
- 1 exact Windows runtime/dependency-pin test.

Platform-independent target: **270 tests**.

The full gate also includes Python compilation, Ruff lint/format, dependency-security verification, transitive lock/SBOM capture, online OSV audit, Alembic consistency, 42-rule/126-fixture governance, ATT&CK v19.1 checks, connector normalization, advanced correlation, API security, grounded/hybrid/adaptive RAG verification, live SQLite-vector/Ollama smoke testing, deterministic regression pipelines, canonical OpenAPI verification, Streamlit-to-React parity verification, TypeScript checking, Vite production build, npm high/critical audit, repository hygiene and release-manifest integrity.

Before distribution or deployment, verify the clean source archive:

```powershell
python -m scripts.verify_source_archive "D:\projects\ThreatLensAI_v0.12_FULL_FEATURE_PARITY_RC.zip"
```

## Runtime configuration

See `.env.example`. Important RAG variables:

```text
THREATLENS_RAG_ENABLED
THREATLENS_OLLAMA_URL
THREATLENS_RAG_STANDARD_LLM_MODEL
THREATLENS_RAG_DEEP_LLM_MODEL
THREATLENS_RAG_LLM_MODEL
THREATLENS_RAG_EMBEDDING_MODEL
THREATLENS_RAG_VECTOR_BACKEND
THREATLENS_RAG_VECTOR_PATH
THREATLENS_RAG_EMBEDDING_BACKEND
THREATLENS_RAG_COLLECTION
THREATLENS_RAG_TOP_K
THREATLENS_RAG_EMBED_BATCH_SIZE
THREATLENS_RAG_MIN_RELEVANCE
THREATLENS_RAG_INCLUDE_ANALYST_NOTES
THREATLENS_RAG_OLLAMA_NUM_CTX
THREATLENS_RAG_OLLAMA_NUM_PREDICT
THREATLENS_RAG_DEEP_READ_TIMEOUT_SECONDS
THREATLENS_RAG_DEEP_OLLAMA_NUM_CTX
THREATLENS_RAG_DEEP_OLLAMA_NUM_PREDICT
THREATLENS_RAG_AUTO_DEEP_THRESHOLD
THREATLENS_RAG_FALLBACK_TO_STANDARD
THREATLENS_RAG_STANDARD_FALLBACK_MAX_PRIMARY_SECONDS
THREATLENS_RAG_EXACT_KNOWLEDGE_LIMIT
THREATLENS_RAG_API_TIMEOUT_SECONDS
```

The legacy `THREATLENS_RAG_CHROMA_PATH` environment variable is accepted for one release only as a migration alias; the former default `data/rag/chroma_db` is automatically mapped to the safe SQLite path and ChromaDB is never imported or installed.

## Release documentation

Current:

- `docs/PROJECT_STATUS_v0.12.0.md`
- `docs/RELEASE_NOTES_v0.12.0.md`
- `docs/FEATURE_PARITY_v0.12.md`
- `docs/DATA_MIGRATION_v0.11.1_to_v0.12.md`
- `docs/LOCAL_UAT_v0.12.md`
- `docs/DEPLOYMENT_v0.12.0.md`
- `docs/FEATURE_PARITY_PHASE_HANDOFF.md`
- `docs/openapi_v0.12.0.json`
- `sbom/source-dependencies-v0.12.0.cdx.json`

Historical v0.10/v0.11.0 documents and manifests are retained as earlier-release evidence.

## Roadmap

- **v0.10.0:** grounded local RAG with governed retrieval, citations and security controls.
- **v0.11.0:** adaptive Standard/Deep local-model routing and deterministic degraded fallback.
- **v0.11.1:** dependency-security closure, built-in SQLite vector persistence, SBOM/lock attestation and release-document correction.
- **v0.12:** React/Vite production SOC console with full legacy feature parity, deployable FastAPI/database architecture, governed data migration, remote inference and operational observability.
- **v1.0:** final end-to-end security/performance/UAT release closure.

ThreatLens is an engineering demonstration architecture, not a replacement for a production SIEM/SOAR. Deterministic evidence remains authoritative; AI is an auditable investigation aid.
