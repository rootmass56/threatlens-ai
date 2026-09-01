# Remaining Industrial Roadmap after v0.8

## v0.9 — FastAPI, Authentication and RBAC

- versioned REST API and OpenAPI contract;
- secure authentication and password hashing;
- analyst, investigator, lead and administrator roles;
- object-level authorization;
- account lockout, rate limiting and secure error handling;
- Streamlit communicating through the API instead of direct database access;
- API integration and authorization tests.

## v0.10 — Grounded Local RAG Investigation Assistant

- curated knowledge ingestion and provenance;
- ChromaDB vector index;
- Ollama-compatible local model integration;
- incident and ATT&CK-grounded retrieval;
- inline citations and insufficient-evidence refusal;
- prompt-injection and untrusted-log defenses;
- groundedness, citation, refusal and latency evaluation.

## v0.11 — PostgreSQL, Docker and Operations

- PostgreSQL migration profile, pooling and indexes;
- Docker Compose and persistent volumes;
- health/readiness checks;
- secrets management;
- structured logs and metrics;
- backup, restore and rollback exercises;
- concurrent-user and performance testing.

## v1.0 — Security Evaluation and Submission

- critical-path coverage targets;
- parser fuzzing and malformed-input testing;
- authentication and authorization security testing;
- API and dependency review;
- RAG prompt-injection evaluation;
- performance benchmark report;
- deployment, administrator, analyst and rule-authoring guides;
- final report, presentation, demonstration video and viva preparation.
