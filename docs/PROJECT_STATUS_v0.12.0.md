# ThreatLens AI v0.12.0 Production Web Platform — Release Candidate Status

## Purpose

v0.12.0 turns the immutable v0.11.1 local SOC runtime into a production-oriented web platform without changing the core authority model: deterministic detection/correlation and persisted evidence remain authoritative; generative AI explains only authorized evidence and governed knowledge.

## Production architecture

```text
Browser
  |
  | HTTPS
  v
Vercel — React 19 + Vite 8 SOC SPA
  |
  | Bearer JWT + CORS allowlist
  v
Render — Dockerized FastAPI
  |
  +--> Render PostgreSQL — SOC persistence
  |        |
  |        +--> pgvector — governed RAG embeddings
  |
  +--> Authenticated HTTPS Ollama-compatible inference
           |
           +--> Standard: Qwen3.5 4B
           +--> Deep: Qwen3.5 9B
           +--> Embedding: Qwen3-Embedding 0.6B / 1024d
```

Local development deliberately remains lighter:

```text
React/Vite :5173 -> FastAPI :8000 -> SQLite + SQLite vector store -> local Ollama :11434
```

## Delivered in the RC tree

- React/Vite production SOC console with complete legacy analyst feature parity: upload/current/history analysis, incident/case workflow, evidence/notes/audit, attack graph, grounded AI investigation/history, ATT&CK coverage/Navigator, detection engineering/quality/fixtures, connector diagnostics, reports, RAG administration and user/security administration.
- Existing FastAPI 44-path/45-operation API boundary retained instead of introducing a duplicate UI-specific backend.
- PostgreSQL URL normalization for managed-platform `postgres://` / `postgresql://` connection strings.
- Conservative SQLAlchemy connection pooling for production.
- Native pgvector RAG backend preserving all governed `KnowledgeChunk` fields.
- Best-effort HNSW creation isolated from vector-table durability.
- SQLite vector backend retained for local development and tests.
- Bearer API-key support for authenticated remote Ollama-compatible inference.
- Qwen3.5 compact-model defaults: 4B Standard and 9B Deep.
- Qwen3-Embedding-0.6B retained at 1024 dimensions.
- Dockerfile, staging-friendly Render Blueprint, secure production startup and Vercel configuration.
- Alembic batch rendering restricted to SQLite; PostgreSQL uses native migrations. Render Free staging applies idempotent migrations at single-instance startup; paid/scaled production moves them to pre-deploy/CI.
- Frontend release gate: dependency install, TypeScript, Vite build and high-severity npm audit.
- v0.12 production-web + feature-parity/migration regression suite: 25 tests.

## Release gates

A production freeze requires all of the following, in order:

1. Python compile, Ruff lint and Ruff format.
2. Reviewed direct dependency contract.
3. Fresh resolved dependency attestation and online OSV audit.
4. 270 platform-independent governed tests.
5. One exact Windows/Python 3.11 runtime-pin test (271 Windows total).
6. Alembic migration consistency on SQLite and PostgreSQL.
7. Detection, ATT&CK, connector, correlation, API-security and RAG gates.
8. React dependency installation / lockfile creation.
9. TypeScript typecheck.
10. Vite production build.
11. npm audit with no high/critical finding accepted without explicit review.
12. PostgreSQL + pgvector integration smoke test.
13. Authenticated remote inference health test.
14. Canonical OpenAPI v0.12 snapshot.
15. v0.12 SBOM and release manifest regeneration.
16. Secret/runtime-artifact/repository hygiene scan.
17. Clean RC ZIP audit and SHA-256.
18. Staging deployment to Render/Vercel (Free tier is demo/staging only).
19. Production UAT and security validation.
20. Immutable v0.12 production freeze.

## Current RC limitation

The feature-parity source is intentionally **not** a production freeze. The target Windows workstation must still generate/verify the lockfile, pass the real TypeScript + Vite + npm-audit gate, pass the complete 271-test governed matrix, perform the guarded v0.11.1 operational-data migration where applicable, and complete the feature-parity UAT checklist. Only then can PostgreSQL/pgvector staging, hosted inference, Render/Vercel live UAT and the final immutable archive proceed.
