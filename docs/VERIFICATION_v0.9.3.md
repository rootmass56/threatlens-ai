# ThreatLens AI v0.9.3 Verification

## Authoritative Windows gate

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

Expected governed matrix: **144 tests**.

- core/multi-source: 49
- v0.4-v0.8 regressions: 23
- v0.9-v0.9.3 auth/RBAC/correctness/security/release integrity: 71
- exact runtime pins: 1

The suite also checks compilation, Ruff, formatting, Alembic `c31f9a7d4e20`, 42 rules/126 fixtures, ATT&CK v19.1, connectors, correlation/graphs, six-role security, Linux 9/4/1/0, multi-source 22/8/2/0, exact OpenAPI, repository hygiene and release-manifest integrity.

## Post-commit distributable gate

Create the ZIP outside the source repository and verify the actual archive:

```powershell
git archive --format=zip --output "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.3_FINAL.zip" HEAD
python -m scripts.verify_source_archive "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.3_FINAL.zip"
```

After the candidate ZIP passes, create the annotated tag, recreate the ZIP from `v0.9.3`, and verify the tagged ZIP again.
