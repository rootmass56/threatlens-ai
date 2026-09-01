# ThreatLens AI v0.9.5 Verification

Run on Windows from the repository root:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

Expected governed matrix:

- core/multi-source: 49
- v0.4-v0.8 regressions: 23
- v0.9-v0.9.5 auth/RBAC/UAT/concurrency/correctness/security/release: 101
- exact Windows runtime/build pins: 1
- total: **174**

Other mandatory gates: Python compilation, Ruff lint/format, Alembic no-drift + head `c31f9a7d4e20`, 42 rules/126 fixtures, ATT&CK v19.1 all domains with exact source SHA pins, connector normalization, advanced correlation/graphs, security verifier, Linux 9/4/1/0, five-source 22/8/2/0, exact OpenAPI 39 paths/40 operations with PDF media type, repository hygiene and v0.9.5 release-manifest integrity.

Targeted UAT rechecks before tagging:

- no-op workflow does not add an audit record;
- real workflow change still audits once;
- PDF contains case notes/evidence and separates incident-linked timelines from additional analysis events;
- multi-source demo preserves the entered analysis name;
- Viewer sees read-only workflow/notes/evidence and backend denial remains intact;
- selected incident/current analysis/sidebar context stay synchronized;
- telemetry/evidence upload widgets explain the rounded decimal-MB browser transport cap while enforcing the exact API byte limit;
- no-op workflow UI explicitly reports that no state/audit change occurred;
- PDF response actions are kept together without an orphaned final recommendation page;
- Rule Catalog displays repository-relative source paths.

After commit, verify the actual Git archive before and after tagging:

```powershell
git archive --format=zip --output "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.5_FINAL.zip" HEAD
python -m scripts.verify_source_archive "D:\projects\ThreatLensAI_Releases\ThreatLensAI_v0.9.5_FINAL.zip"
```

Only then create `v0.9.5`, recreate the archive from the tag and run `verify_source_archive` again. Final approval requires independent audit of that exact tagged ZIP.
