# Migration: ThreatLens AI v0.9.2 to v0.9.3

v0.9.3 adds one database migration and correctness/security hardening. RAG remains absent.

```powershell
alembic upgrade head
```

Expected head: `c31f9a7d4e20`.

The migration adds nullable `analysis_fingerprint` and non-null JSON `analysis_context_json` to existing `analysis_sessions`. Existing sessions are preserved. Because their original parser-option/rule-build semantics cannot always be reconstructed safely, legacy sessions are not retroactively assigned a potentially misleading semantic fingerprint. New v0.9.3 analyses populate both fields.

After migration run the full verifier:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```
