# ThreatLens AI v0.4 Verification Evidence

## Automated gate

Run:

```powershell
.\scripts\verify.ps1
```

Expected evidence:

- compilation passes
- Ruff linting passes
- Ruff formatting passes
- 32 tests pass
- tested app/core/database scope coverage is approximately 87%
- Alembic reports no model changes
- active revision is `e48a7c9d2f10 (head)`
- rule catalog validates
- sample output is `(9 events, 4 alerts, 1 incident, 0 quarantined)`
- imports pass

## Rule fixtures

The catalog contains four rules and twelve fixture cases:

- positive
- negative
- boundary

All cases must pass before the catalog can be considered release-ready.

## Migration evidence

The v0.4 migration adds common-schema/parser fields to events and sessions, plus rule governance and risk metadata to alerts. Upgrade and downgrade functions are included.
