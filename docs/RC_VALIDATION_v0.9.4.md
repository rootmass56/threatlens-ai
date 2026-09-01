# ThreatLens AI v0.9.4 Release-Candidate Validation

This candidate is built from the exact immutable v0.9.3 final source archive and contains only deterministic correctness/security/configuration hardening plus governed evidence for those changes.

Required release sequence:

1. overlay candidate on a branch created from tag `v0.9.3`;
2. run `scripts/setup.ps1`;
3. run the complete `scripts/verify.ps1` gate;
4. stage all release files and rerun the complete gate against the exact staged state;
5. commit without source changes;
6. create and verify an external ZIP from `HEAD`;
7. create annotated tag `v0.9.4` only after the HEAD ZIP passes;
8. recreate the external ZIP from `v0.9.4`, verify it again and calculate SHA-256;
9. independently audit that exact tagged ZIP before v0.10.

The audit container can execute platform-independent tests and negative/concurrency probes, but the user's exact Windows CPython 3.11 dependency/runtime gate remains authoritative for release approval.
