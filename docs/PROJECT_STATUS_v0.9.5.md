# ThreatLens AI Project Status — v0.9.5 Pre-RAG UAT Closure Candidate

v0.9.5 preserves the complete deterministic SOC platform and closes defects reproduced through full browser UAT of the immutable v0.9.4 source baseline.

Current capabilities remain: five telemetry connectors, Common Event Schema normalization, 42 governed rules/126 fixtures, complete pinned MITRE ATT&CK v19.1 Enterprise/Mobile/ICS catalogue awareness, evidence-backed Enterprise mappings, explainable cross-source entity/relationship correlation, persistent attack graphs, case workflow/notes/evidence/audit, FastAPI authentication, six-role RBAC, semantic analysis identity, deterministic PDF reports and immutable release-manifest/archive verification.

UAT remediation adds no-op audit suppression, case-scoped report timelines, notes/evidence report sections, exact PDF OpenAPI media metadata, user-controlled multi-source naming, read-only Viewer Case Details, synchronized selected-case/sidebar state, API-derived Streamlit upload caps and repository-relative rule provenance.

The governed release gate targets **174 Windows tests**: 49 core/multi-source + 23 v0.4-v0.8 + 101 v0.9-v0.9.5 + 1 exact runtime/build pin test. Alembic head remains `c31f9a7d4e20`; OpenAPI remains 39 paths / 40 operations.

RAG remains intentionally absent. v0.10 starts only after the exact tagged v0.9.5 archive passes final independent audit.
