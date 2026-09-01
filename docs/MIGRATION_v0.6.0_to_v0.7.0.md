# Migration: ThreatLens AI v0.6.0 to v0.7.0

## Before installation

- Confirm `v0.6.0` is tagged and the working tree is clean.
- Create branch `feature/v0.7-attack-sync-and-coverage` from `v0.6.0`.
- Preserve `.git`, `.env`, `.streamlit/secrets.toml`, and `database/threatlens.db`.

## Database migration

v0.7 adds Alembic revision:

```text
f7b6c91a2d04
```

It creates four ATT&CK tables without altering existing analyses, events, alerts, incidents,
notes, evidence, or audit records.

## Setup

```powershell
.\scripts\setup.ps1
```

The setup script installs dependencies, upgrades Alembic, downloads all three pinned official
ATT&CK v19.1 bundles, validates exact catalog counts, and persists every STIX object and
relationship.

To install dependencies and migrations without downloading ATT&CK data:

```powershell
$env:THREATLENS_SKIP_ATTACK_SYNC = "1"
.\scripts\setup.ps1
```

This mode is intended only for controlled troubleshooting. Full v0.7 verification requires the
catalogs.

## Manual synchronization

```powershell
python -m scripts.sync_attack_catalog --domain all --actor saketh
```

Offline reuse after the bundles have been downloaded:

```powershell
python -m scripts.sync_attack_catalog --domain all --offline --actor saketh
```

## Acceptance gate

```powershell
.\scripts\verify.ps1
```

The gate requires:

- Python compilation;
- Ruff lint and format checks;
- all automated tests;
- Alembic head `f7b6c91a2d04` with no model drift;
- 42 governed rules and 126 fixtures;
- complete Enterprise, Mobile, and ICS v19.1 counts;
- valid Enterprise rule mappings;
- Navigator export validation;
- connector and analytics regressions.
