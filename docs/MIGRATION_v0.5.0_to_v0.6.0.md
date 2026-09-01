# Migration Guide: v0.5.0 to v0.6.0

## Database

No new database migration is required. The Alembic head remains:

```text
e48a7c9d2f10
```

## Source update

Preserve these local resources from the existing project:

- `.git`
- `.env`
- `database/threatlens.db`

Replace the remaining source with the v0.6 package, recreate `.venv`, run setup and execute the full verification suite.

## New configuration

`config/rule_profiles.yml` is introduced. The default profile preserves standard rule behavior.

Optional PowerShell selection:

```powershell
$env:THREATLENS_RULE_PROFILE = "lab"
```

Unset the variable or select `default` before release verification.

## Acceptance targets

```text
42 valid rules
126 fixture cases passed
46 automated tests passed
Linux sample: 9 4 1 0
Multi-source sample: 22 8 2 0
Alembic: e48a7c9d2f10 (head)
```
