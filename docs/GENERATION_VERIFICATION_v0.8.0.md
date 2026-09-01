# ThreatLens AI v0.8.0 Generation Verification

The generated source package is accepted only after a fresh extraction verifies:

- required source and documentation files;
- no `.git`, `.venv`, `.env`, SQLite database, downloaded ATT&CK bundle, cache or generated report;
- Python compilation;
- automated tests available in the packaging environment;
- fresh SQLite Alembic upgrade to `a8c4e2d1f903`;
- Alembic model-drift check;
- advanced-correlation verifier;
- Linux and multi-source regression outputs;
- ZIP integrity and SHA-256 checksum.

PowerShell, Streamlit runtime startup, Ruff and network-backed complete ATT&CK synchronization are
re-run on the target Windows environment through `scripts/verify.ps1`. Packaging verification does
not substitute for that final platform-specific acceptance gate.
