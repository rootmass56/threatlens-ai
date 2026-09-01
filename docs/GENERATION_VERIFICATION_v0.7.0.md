# ThreatLens AI v0.7.0 Generation Verification

## Packaging-environment checks

The generated v0.7 source tree passed:

- Python syntax compilation for application, ATT&CK, core, database, migration, script, and test
  packages;
- 58 automated tests available in the packaging environment;
- 42 governed detection rules and 126 fixture cases;
- 100% detection-rule governance score;
- Alembic upgrade to `f7b6c91a2d04` in a clean temporary SQLite database;
- Alembic model-drift check with no new operations detected;
- source line-length inspection for the Ruff-controlled Python scope;
- clean archive extraction and structural inspection.

The packaging environment could not download the large official ATT&CK bundles and did not
contain Ruff or the Windows PowerShell runtime. It therefore does not claim that official-bundle,
Ruff, Streamlit-runtime, or PowerShell gates were executed there.

## Authoritative Windows acceptance gate

After installation on the project computer, run:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\setup.ps1
.\scripts\verify.ps1
```

The Windows gate must confirm:

- 59 automated tests, including the pinned Streamlit/Starlette runtime test;
- Ruff linting and formatting;
- Alembic head `f7b6c91a2d04`;
- all three official ATT&CK v19.1 bundles;
- exact counts of 39 tactics, 378 techniques, and 540 sub-techniques across all domains;
- 918 active technique and sub-technique domain records;
- complete persisted object and relationship counts and matching SHA-256 fingerprints;
- zero invalid governed Enterprise mappings;
- valid ATT&CK Navigator output;
- existing Linux and multi-source pipeline regressions.
