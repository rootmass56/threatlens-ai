# ThreatLens AI — v0.11.1 Operational Data Migration to v0.12

## Goal

Bring forward useful SOC investigation data from an existing v0.11.1 SQLite runtime into the v0.12 local runtime without importing obsolete authentication state or replacing v0.12 security/bootstrap configuration.

## Migrated operational data

The migration tool copies the following relational evidence while preserving source primary keys and UUIDs:

- analysis sessions;
- normalized events;
- deterministic alerts;
- incidents;
- alert/event evidence relationships;
- incident/alert relationships;
- correlation runs;
- resolved entities;
- scored correlation relationships;
- incident/entity links;
- attack graph snapshots;
- investigation notes;
- registered evidence;
- persisted incident RAG query history;
- operational audit records for analyses, incidents and RAG knowledge actions.

## Deliberately preserved from v0.12

The migration never imports these v0.11.1 identity/security/catalogue tables:

- security roles;
- user accounts and password hashes;
- user-role memberships;
- refresh tokens;
- login attempts;
- ATT&CK catalogue/object/relationship state;
- rule-to-ATT&CK mapping persistence.

This prevents old credentials, token state or stale ATT&CK material from silently replacing the verified v0.12 environment.

## Safety properties

`scripts/migrate_v0111_operational_data.py`:

1. refuses source==target;
2. requires both SQLite files to pass `PRAGMA integrity_check`;
3. requires both databases to be at the compatible Alembic head;
4. validates ordered operational table schemas exactly;
5. refuses a non-empty v0.12 operational target unless explicit replacement is requested;
6. creates a timestamped SQLite-consistent backup using the SQLite backup API before writing;
7. performs the migration inside one `BEGIN IMMEDIATE` transaction;
8. rolls back on copy failure;
9. re-runs integrity validation after migration;
10. prints machine-readable counts for review.

## Windows workflow

First stop the FastAPI process so the local target database is not serving active UAT traffic.

Dry-run only:

```powershell
.\MIGRATE_V0111_DATA_TO_V012.ps1
```

Apply when the v0.12 operational database is empty:

```powershell
.\MIGRATE_V0111_DATA_TO_V012.ps1 -Apply
```

If the v0.12 database contains only disposable local UAT analyses and you intentionally want to replace them with the old operational data:

```powershell
.\MIGRATE_V0111_DATA_TO_V012.ps1 -Apply -ReplaceOperationalData
```

If the old database is in a non-default location:

```powershell
.\MIGRATE_V0111_DATA_TO_V012.ps1 -SourceDatabase "D:\path\to\old\database\threatlens.db"
```

Never use `-ReplaceOperationalData` against a database whose newer investigation work must be retained. In that situation the correct path is an explicit merge migration, not destructive replacement.
