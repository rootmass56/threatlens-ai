# ThreatLens AI v0.12.0 Deployment Runbook

## Target topology

- Frontend: Vercel (`frontend/`)
- Backend: Render Docker web service
- Database/vector store: Render PostgreSQL + `pgvector`
- Inference: authenticated HTTPS Ollama-compatible endpoint

The included `render.yaml` intentionally uses Render Free resources for **staging/demo deployment**. Render documents Free web services as suitable for hobby/testing use, not production; Free PostgreSQL also expires after 30 days. The final long-lived production freeze must upgrade the service/database or move the database to a persistent managed PostgreSQL provider.

## 1. Local release verification

On Windows PowerShell from the project root, use the top-level gate:

```powershell
.\INSTALL_THREATLENS_V012_AND_VERIFY.ps1
```

This creates/verifies the Python 3.11 environment, synchronizes ATT&CK, pulls the configured local Qwen models, requires an online dependency audit, runs the 271-test Windows matrix, and executes the React/Vite install/typecheck/build/npm-audit gate. Do not deploy if it fails.

Vite 8 requires Node.js 20.19+ or 22.12+; current Node.js LTS is recommended.

## 2. Feature-parity local UAT and optional data migration

Before any cloud deployment, run `RUN_THREATLENS_V012_UAT.ps1` and complete `docs/LOCAL_UAT_v0.12.md`. If a v0.11.1 working database contains analyst/demo data that should be retained, run `MIGRATE_V0111_DATA_TO_V012.ps1` in dry-run mode first, review the source/target counts, then apply the migration. Never copy the old database over the v0.12 database because v0.12 security identity and token state must remain authoritative.

## 3. Staging backend/database on Render

Create a Blueprint from the repository root. The included `render.yaml` provisions:

- a Dockerized `threatlens-api` web service;
- PostgreSQL for SOC persistence;
- the same PostgreSQL database for pgvector-backed RAG;
- Singapore region defaults for the staging Blueprint;
- automatic deploy disabled so a reviewed commit is deployed deliberately.

Because Render Free does not support pre-deploy commands, `scripts/start_production.sh` runs idempotent Alembic migrations and security bootstrap before starting FastAPI. For a paid/scaled deployment, move migrations back to a Render pre-deploy command or CI migration job to avoid multiple instances racing migrations.

## 4. Required backend secrets and variables

Set these secret values in Render before the first successful startup:

```text
THREATLENS_JWT_SECRET=<48+ random characters>
THREATLENS_BOOTSTRAP_ADMIN_PASSWORD=<strong unique initial admin password>
THREATLENS_ALLOWED_ORIGINS=https://<your-vercel-domain>
THREATLENS_TRUSTED_HOSTS=<your-render-hostname>
THREATLENS_OLLAMA_URL=https://<your-inference-endpoint>
THREATLENS_OLLAMA_API_KEY=<inference secret>
```

The bootstrap password is consumed from the environment; ThreatLens does not write a plaintext credential file when an explicit bootstrap password is supplied.

Production RAG defaults in the Blueprint are:

```text
THREATLENS_RAG_VECTOR_BACKEND=pgvector
THREATLENS_RAG_EMBEDDING_DIMENSIONS=1024
THREATLENS_RAG_STANDARD_LLM_MODEL=qwen3.5:4b
THREATLENS_RAG_DEEP_LLM_MODEL=qwen3.5:9b
THREATLENS_RAG_EMBEDDING_MODEL=qwen3-embedding:0.6b
```

If the hosted inference provider uses different model tags, override them with environment variables. Never change model tags in code solely for deployment.

## 5. Initialize governed RAG knowledge

After the API can reach the production embedding endpoint:

1. Sign in with the bootstrap administrator.
2. Open **System**.
3. Select **Re-index governed knowledge**.
4. Confirm `/api/v1/rag/health` reports the pgvector backend and a nonzero indexed-chunk count.

The operation is protected by `rag:manage`; unauthorized users receive the normal RBAC denial. CLI initialization remains available as `python -m scripts.production_init` on environments with shell/job access.

## 6. Frontend on Vercel

Deploy the `frontend/` directory. Configure only:

```text
VITE_THREATLENS_API_URL=https://<your-render-api-host>
```

This URL is public by design. Never put JWT secrets, database URLs, Ollama keys or other secrets in any `VITE_*` value because Vite bundles them into browser JavaScript.

The Vercel config includes SPA routing plus nosniff/frame/referrer/permissions controls and a Content Security Policy. The frontend uses the API's refresh-token rotation and clears the browser session if refresh fails or token reuse is detected.

## 6. Production UAT

Verify at minimum:

- login, invalid login and account lockout;
- access-token expiry followed by refresh-token rotation;
- refresh-token reuse rejection and logout;
- all six RBAC roles;
- telemetry upload and deterministic pipeline outputs;
- incident queue and workflow changes;
- ATT&CK/rule pages;
- Auto/Standard/Deep assistant modes;
- citation IDs resolve only to authorized evidence/knowledge;
- prompt-injection and secret-extraction refusal;
- Deep-to-Standard and deterministic degradation behavior;
- pgvector count/retrieval after backend restart;
- CORS rejects unapproved origins;
- production API docs remain disabled;
- no secret appears in frontend static assets;
- mobile and desktop UI behavior;
- Render liveness/readiness endpoints;
- Vercel production domain calls only the intended API;
- RAG re-index requires `rag:manage`.

## 7. Production upgrade and immutable freeze

The free Render resources are a staging/demo target, not the final long-lived production tier. Before calling v0.12 a production freeze:

1. upgrade Render web/database resources (or move PostgreSQL to a durable managed provider);
2. move migrations to a paid pre-deploy/CI migration job if scaling beyond one API instance;
3. run staging UAT against the exact production inference service;
4. regenerate OpenAPI, SBOM and `RELEASE_MANIFEST_v0.12.0.json`;
5. perform clean ZIP/security/secret/archive audits;
6. record the final source SHA-256;
7. deploy the exact frozen commit/archive;
8. run post-deployment smoke/UAT/security checks;
9. mark v0.12 immutable only after all gates are green.
