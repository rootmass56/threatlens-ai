# ThreatLens AI v0.9.4 Verification

Run on Windows from the repository root:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

Expected governed matrix:

- core/multi-source: 49
- v0.4-v0.8 regressions: 23
- v0.9-v0.9.4 auth/RBAC/concurrency/correctness/security/release: 84
- exact Windows runtime/build pins: 1
- total: **157**

Other mandatory gates: Ruff lint/format, Alembic no-drift + head `c31f9a7d4e20`, 42 rules/126 fixtures, ATT&CK v19.1 all domains with exact source SHA pins, connector normalization, advanced correlation/graphs, security verifier, Linux 9/4/1/0, five-source 22/8/2/0, OpenAPI 39/40 exact, repository hygiene and v0.9.4 release manifest.

After commit, verify the actual Git archive before and after tagging:

```powershell
git archive --format=zip --output "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.4_FINAL.zip" HEAD
python -m scripts.verify_source_archive "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.4_FINAL.zip"
```

Only then create `v0.9.4`, recreate the archive from the tag and run `verify_source_archive` again.
