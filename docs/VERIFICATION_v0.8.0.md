# ThreatLens AI v0.8.0 Verification Evidence

## Required gates

```powershell
python -m compileall app attack correlation core database scripts tests migrations
ruff check app attack correlation core database tests scripts migrations\env.py
ruff format app attack correlation core database tests scripts migrations\env.py --check
pytest -q
alembic check
alembic current
python -m scripts.verify_detection_catalog
python -m scripts.verify_attack_catalog
python -m scripts.verify_advanced_correlation
.\scripts\verify.ps1
```

## Advanced-correlation acceptance conditions

- Linux remains 9 events, 4 alerts, 1 incident and 0 quarantined.
- Multi-source remains 22 events, 8 alerts, 2 incidents and 0 quarantined.
- Multi-source correlation uses 7 representatives and records 1 semantic duplicate.
- Both multi-source incidents are multi-source and multi-stage.
- Entity and relationship minimums pass.
- Required graph node and edge layers exist.
- Graph schema equals `threatlens-attack-graph-1.0`.
- Graph SHA-256 is 64 hexadecimal characters and matches the payload.
- Persisted graph counts match snapshot contents.
- Alembic head is `a8c4e2d1f903`.

## UI acceptance

- Attack Graph Investigation loads a persisted v0.8 analysis.
- Layer, confidence and incident filters work.
- Entities, relationships and storylines are visible.
- JSON and CSV exports download.
- Case Details shows correlation evidence.
- Reports show stage progression and graph metrics.
- Restarting the application preserves the graph and incident evidence.
