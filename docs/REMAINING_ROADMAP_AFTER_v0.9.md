# Remaining Roadmap After ThreatLens AI v0.9

## v0.10 — Grounded RAG analyst assistant

- Curated knowledge ingestion for ATT&CK, governed rules, parsers, playbooks and project policy
- ChromaDB collections, metadata, hashes, versions and incremental indexing
- Local Ollama-hosted Qwen model
- Incident/evidence-grounded questions and answers
- Citations, uncertainty and refusal when support is insufficient
- Prompt-injection defense, source allowlists and output validation
- Retrieval, groundedness, citation, refusal, latency and memory evaluation

## v0.11 — PostgreSQL, Docker and operational hardening

- PostgreSQL profile, pools, indexes and concurrency tests
- Migration upgrade/downgrade and backup/restore tests
- Docker Compose for Streamlit, FastAPI, PostgreSQL, ChromaDB and Ollama
- Persistent volumes, health/readiness, secret injection and startup ordering
- HTTPS-capable reverse proxy and shared rate limiting
- Structured logs, metrics, retention and offline demonstration mode

## v1.0 — Final evaluation and release

- 80% overall and 90% critical-path automated coverage targets
- Parser, rule, correlation, graph, database, API, report and RAG benchmarks
- Upload abuse, traversal, parser fuzzing, injection, authorization, token and prompt-injection tests
- Complete role-based UAT
- Linux, Windows, network, ATT&CK, graph, case, RAG and deployment demonstrations
- Architecture, threat model, API, database, testing, deployment and analyst documentation
- Final report, presentation, demo video, GitHub release and interview preparation

## Scope discipline

Do not add random cloud, streaming, SOAR or machine-learning features before the mandatory v1.0 gates. One bounded identity/cloud connector may be considered only after v0.11 if it does not delay security evaluation.
