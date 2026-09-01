# Migration: ThreatLens AI v0.8.0 to v0.9.0

## Database revision

```text
v0.8 head: a8c4e2d1f903
v0.9 head: b9f7d3c2a104
```

The migration adds security roles, accounts, role assignments, refresh-token state and login-attempt evidence. Existing analyses, events, alerts, incidents, ATT&CK catalogues and attack graphs are preserved.

## Safe upgrade sequence

1. Stop Streamlit and any API process.
2. Back up the project and SQLite database.
3. Install the complete v0.9 source while preserving `.git`, `.env`, database and downloaded ATT&CK bundles.
4. Recreate or update `.venv` from `requirements.txt` and `requirements-dev.txt`.
5. Run `alembic upgrade head`.
6. Run `python -m scripts.bootstrap_security`.
7. Record the generated administrator credentials securely.
8. Run `python -m pip check`.
9. Run `python -m scripts.verify_security_api`.
10. Run `./scripts/verify.ps1`.

## Configuration additions

v0.9 may add the following values to `.env`:

- JWT signing secret, issuer and audience
- access/refresh lifetimes
- lockout threshold and duration
- API URL, host and port
- allowed origins and trusted hosts
- upload count/size limits
- development-docs flag

The bootstrap script preserves existing values and only generates missing security defaults.

## First login

When no password is supplied through environment variables, bootstrap writes a one-time credential file under `data/`. The file is excluded from Git. Change the password through Security Administration and delete the file after recording the credential securely.

## Rollback warning

Downgrading removes authentication and role tables. Export any required audit/security evidence before running an Alembic downgrade. Do not downgrade a tagged project without preserving the database backup.
