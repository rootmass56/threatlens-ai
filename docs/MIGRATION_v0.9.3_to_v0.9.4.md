# Migration: ThreatLens AI v0.9.3 to v0.9.4

v0.9.4 has **no database schema migration**. Alembic head remains `c31f9a7d4e20`.

Run `scripts/setup.ps1` so exact release build tooling/direct dependency constraints are applied, then run the complete verification suite. Existing v0.9.3 semantic fingerprint/context data remains valid.

Database configuration is now resolved consistently by `database/session.py`: process `THREATLENS_DATABASE_URL` first, repository `.env` second, and the local SQLite default last. If a custom database is configured in `.env`, Alembic, bootstrap and application runtime now resolve that same target.
