# Remaining Industrial Roadmap after v0.6

## v0.7 — Official MITRE ATT&CK service

- synchronize Enterprise ATT&CK through versioned STIX/TAXII data
- persist tactics, techniques, sub-techniques, relationships and lifecycle flags
- store mapping justification, confidence and telemetry requirements
- create coverage matrix and detection-gap views
- export ATT&CK Navigator-compatible JSON layers

## v0.8 — Advanced correlation and attack graphs

- entity resolution for users, hosts, IP addresses, processes, files and domains
- alert deduplication and suppression across analyses
- ordered multi-stage attack storylines
- relationship confidence and cross-source correlation
- interactive attack graph and graph JSON export

## v0.9 — FastAPI, authentication and RBAC

- service-backed UI
- authentication, password hashing and session/token lifecycle
- viewer, analyst, senior analyst, rule engineer and administrator roles
- object-level authorization, rate limits, request IDs and secure errors
- OpenAPI contracts and API tests

## v0.10 — Grounded RAG analyst assistant

- approved knowledge ingestion
- ChromaDB retrieval
- local Ollama/Qwen integration
- citations, refusal behavior and prompt-injection defenses
- groundedness, citation and latency evaluation

## v1.0 — Deployment and final evaluation

- PostgreSQL profile
- Docker Compose
- backup/restore and health checks
- performance, security and user-acceptance testing
- final report, presentation, demo recording and release documentation
