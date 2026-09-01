# ThreatLens AI v0.12.0 Production Web Platform

v0.12.0 is the production-web evolution of the immutable v0.11.1 security-closed baseline.

Highlights:

- React 19 + Vite 8 SOC frontend for Vercel.
- Dockerized FastAPI backend for Render.
- managed PostgreSQL persistence and native pgvector production RAG.
- SQLite persistence/vector retrieval retained for local development.
- authenticated HTTPS remote Ollama-compatible inference.
- Qwen3.5 4B Standard and Qwen3.5 9B Deep default generation profiles.
- Qwen3-Embedding-0.6B 1024-dimensional retrieval profile retained.
- PostgreSQL-aware Alembic configuration and connection pooling.
- 25 v0.12 production-web/feature-parity regression tests, bringing the intended governed matrix to 270 platform-independent tests / 271 exact Windows tests.
- deployment, frontend build/audit and production initialization gates.
- complete React migration of all 15 analyst-facing Streamlit surfaces, governed by `config/frontend_feature_parity_v0.12.json`.
- guarded v0.11.1 operational-data migration that preserves v0.12 users/roles/credentials/tokens and creates an automatic pre-migration target backup.
- safer CPU-local RAG embedding default (`batch_size=4`) and explicit local UAT launcher with bindable backend-port probing.

The release remains a candidate until the target Windows 271-test/frontend/security gate, feature-parity local UAT and data migration (when applicable), PostgreSQL/pgvector integration, hosted-inference smoke test and Render/Vercel deployment UAT pass.
