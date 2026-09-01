# ThreatLens AI v0.5.0 Verification Evidence

## Release gates

The `scripts/verify.ps1` workflow is fail-fast. A non-zero command exit stops the release check immediately.

The release gate performs:

1. Python source compilation.
2. Ruff linting with `E`, `F`, `I`, `UP` and `B` rule families.
3. Ruff formatting verification.
4. The complete pytest suite.
5. Alembic model/migration drift detection.
6. Active migration revision inspection.
7. Validation of 12 YAML rules and 36 fixture cases.
8. Exact Linux regression smoke test: `9 / 4 / 1 / 0`.
9. Exact multi-source smoke test: `22 / 8 / 2 / 0`.
10. Package import smoke test.

## Expected release output

```text
Linux sample: 9 4 1 0
Multi-source sample: 22 8 2 0
12 validated rules
36/36 fixture cases passed
38 tests passed
All ThreatLens AI v0.5 verification checks passed.
```

## Acceptance interpretation

- A connector is accepted only when it normalizes supported fixtures, reports validation evidence and quarantines malformed input.
- A rule is accepted only when its schema and metadata validate and its positive, negative and boundary fixtures pass.
- Multi-source support is accepted only when event identifiers remain unique, connector provenance is retained and the combined pipeline is persistable.
- Existing Linux behavior must remain unchanged.
