# Migration: ThreatLens AI v0.7.0 to v0.8.0

## Git preparation

Create `feature/v0.8-advanced-correlation-attack-graph` from the verified `v0.7.0` tag and keep
the v0.7 project backup until v0.8 verification and UI acceptance are complete.

## Database migration

v0.8 adds Alembic revision:

```text
a8c4e2d1f903
```

It preserves all existing analyses, incidents, ATT&CK catalogs, rule mappings, notes, evidence and
audit records. Existing pre-v0.8 analyses remain readable but do not contain graph snapshots.
Re-running their source data under v0.8 creates advanced correlation evidence.

New tables:

- `correlation_runs`
- `correlation_entities`
- `incident_entities`
- `correlation_relationships`
- `attack_graph_snapshots`

New incident fields include correlation version and ID, representative and deduplicated counts,
source/entity/relationship/stage counts, stage progression, graph score, storyline and metadata.

## Setup

```powershell
.\scripts\setup.ps1
```

Setup applies Alembic migrations and preserves pinned ATT&CK synchronization behavior.

## Verification

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
python -m scripts.verify_advanced_correlation
.\scripts\verify.ps1
```

Expected regression outputs remain:

```text
Linux sample: 9 4 1 0
Multi-source sample: 22 8 2 0
```

## Rollback

Before a database downgrade, create an external database backup. Downgrading removes v0.8 graph
and correlation records and the advanced incident columns. It does not reconstruct the legacy
correlation output from a graph snapshot.
