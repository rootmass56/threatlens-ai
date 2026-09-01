# Migration: ThreatLens AI v0.9.5 to v0.10.0

v0.10.0 adds Alembic revision `d4a7c0e51010`, chained from the approved v0.9.5 head `c31f9a7d4e20`.

```powershell
alembic upgrade head
alembic current
```

Expected head:

```text
d4a7c0e51010
```

The migration creates `rag_investigation_queries`, an audit-oriented table linked to incidents. Existing deterministic events, alerts, incidents, correlation data, notes, evidence, users and audit records are not rewritten.

Install the new pinned Python dependency with normal setup and initialize external models/index only when live RAG is desired. Runtime Chroma/index data under `data/rag/` is disposable/rebuildable and is not part of the source release.
