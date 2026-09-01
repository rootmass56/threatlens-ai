# ThreatLens AI Project Status — v0.10.0 Grounded RAG

v0.10.0 builds directly on the approved deterministic v0.9.5 baseline. It adds governed retrieval and local structured generation while preserving deterministic security authority.

Current release targets:

- 42 governed rules / 126 fixtures;
- ATT&CK v19.1 Enterprise, Mobile and ICS;
- Linux baseline 9/4/1/0;
- five-source baseline 22/8/2/0;
- six governed roles;
- Alembic head `d4a7c0e51010`;
- canonical OpenAPI 44 paths / 45 operations;
- 206 Windows governed tests: 205 platform-independent + 1 exact runtime pin;
- offline RAG end-to-end safety/grounding verification;
- optional mandatory live Ollama/Chroma readiness gate.

Deterministic ThreatLens remains usable when the AI runtime is absent. v0.11 remains responsible for PostgreSQL/Docker/shared distributed operational hardening.


## Advanced RAG hardening state

The hardened v0.10 RAG path adds deterministic query planning, exact ATT&CK/rule source
retrieval alongside dense semantic retrieval, explicit cross-incident mismatch refusal,
pre-model refusal for requested facts absent from the authorized incident, short citation
aliases with post-generation restoration, evidence-vs-knowledge citation-plane validation,
and structured per-technique evidence/knowledge explanations.

The Enterprise ATT&CK knowledge loader now targets the actual pinned `enterprise-attack`
catalog domain, so official ATT&CK technique/sub-technique records participate in governed
knowledge indexing instead of silently being skipped.
