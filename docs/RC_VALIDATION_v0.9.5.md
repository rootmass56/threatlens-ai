# ThreatLens AI v0.9.5 Release-Candidate Validation

This candidate is built from the exact immutable v0.9.4 UAT baseline and contains deterministic UAT remediation, release/version evidence and governed regressions only. It does not introduce RAG.

## Final browser-UAT polish gate

The final targeted browser review also requires three presentation-level checks before staging: a true no-op workflow submission must explain that no state/audit change occurred; the PDF recommendation block must not orphan a final action on an otherwise empty page; and telemetry/evidence upload screens must explain the rounded decimal-MB browser transport cap versus the exact MiB/byte API boundary. These clarifications do not change authorization, report evidence semantics, or API upload limits.

Required release sequence:

1. use a clean branch created from tag `v0.9.4`;
2. apply the v0.9.5 candidate source changes without copying runtime databases, `.env`, caches or local reports;
3. run `scripts/setup.ps1` in the exact Windows CPython 3.11 environment;
4. run the complete `scripts/verify.ps1` gate;
5. perform targeted browser re-tests for no-op audit, report content/timeline, multi-source naming, Viewer read-only UI, case/sidebar synchronization and upload limits;
6. stage all release files and rerun the complete gate against the exact staged state;
7. commit without source changes;
8. create and verify an external ZIP from `HEAD`;
9. create annotated tag `v0.9.5` only after the HEAD ZIP passes;
10. recreate the external ZIP from `v0.9.5`, verify it again and calculate SHA-256;
11. independently audit that exact tagged ZIP before v0.10.

The audit container can execute the platform-independent governed tests and static/source-archive checks. The user’s exact Windows CPython 3.11 runtime/dependency pin test, Ruff gate and Windows PowerShell release sequence remain authoritative for final approval.
