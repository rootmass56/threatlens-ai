# ThreatLens AI v0.9.2 Verification

## Authoritative Windows gate

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

The governed Windows matrix contains 129 tests: 49 core/multi-source, 23 v0.4-v0.8 regressions, 56 v0.9-v0.9.2 security/UI/release-integrity tests, and 1 exact runtime-pin test.

## Required post-commit source-archive gate

Create the ZIP outside the repository and verify the actual archive:

```powershell
git archive --format=zip --output "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.2_FINAL.zip" HEAD
python -m scripts.verify_source_archive "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.2_FINAL.zip"
```

Only after that passes should `v0.9.2` be tagged. Recreate the ZIP from the tag and verify it again.
