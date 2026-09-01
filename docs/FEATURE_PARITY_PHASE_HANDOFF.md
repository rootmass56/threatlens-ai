# ThreatLens AI v0.12 — Full Feature-Parity Phase Handoff

This package is the complete **source release candidate** for the Streamlit-to-React feature-parity phase. It is intentionally designed so the target Windows/Python 3.11 machine performs the exact dependency, model, frontend and runtime verification that cannot be truthfully substituted by packaging-host checks.

## Acceptance target

The phase is complete when all of the following are true:

1. `INSTALL_THREATLENS_V012_AND_VERIFY.ps1` passes.
2. The governed Windows matrix reports **271/271**.
3. `python -m scripts.verify_frontend_feature_parity` reports all 15 legacy analyst surfaces migrated/superseded.
4. TypeScript, Vite production build and npm high/critical audit pass.
5. Live Qwen3.5 Standard/Deep + Qwen embedding RAG readiness passes.
6. v0.11.1 operational-data migration is dry-run validated and either applied or consciously waived.
7. `RUN_THREATLENS_V012_UAT.ps1` launches the React/FastAPI/Ollama stack.
8. All 22 governed interactive checks are recorded PASS by `RECORD_FEATURE_PARITY_UAT.ps1`.
9. `FREEZE_THREATLENS_V012_FEATURE_PARITY.ps1` creates and independently verifies the post-UAT source archive.

## Recommended one-command start

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\COMPLETE_FEATURE_PARITY_PHASE.ps1
```

If a non-default legacy database should be migrated, provide it explicitly:

```powershell
.\COMPLETE_FEATURE_PARITY_PHASE.ps1 -SourceDatabase "D:\path\to\v0111\database\threatlens.db"
```

The command performs the full automated release gate and an operational-migration dry-run when a legacy database is supplied/discovered. Apply migration only after reviewing the dry-run counts:

```powershell
.\MIGRATE_V0111_DATA_TO_V012.ps1 -Apply
```

Then launch UAT:

```powershell
.\RUN_THREATLENS_V012_UAT.ps1
```

After all interactive checks pass:

```powershell
.\RECORD_FEATURE_PARITY_UAT.ps1
.\FREEZE_THREATLENS_V012_FEATURE_PARITY.ps1
```

## Deployment remains the next phase

The feature-parity freeze is not the final production freeze. The next phase moves persistence to PostgreSQL/pgvector, selects/verifies production inference, deploys FastAPI/React to Render/Vercel (or the final selected providers), performs live UAT/security checks, and only then freezes the deployed production release.
