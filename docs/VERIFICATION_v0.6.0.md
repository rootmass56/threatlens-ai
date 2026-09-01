# ThreatLens AI v0.6.0 Verification

Run:

```powershell
.\scripts\verify.ps1
```

The verification gate checks:

1. Python compilation.
2. Ruff linting.
3. Ruff formatting.
4. Automated tests.
5. Alembic model consistency.
6. Active migration revision.
7. 42-rule catalogue validation.
8. 126 fixture executions.
9. Lifecycle and review completeness.
10. Dataset distribution.
11. Connector normalization.
12. Linux regression output.
13. Multi-source regression output.
14. Package imports.

The packaging environment verified compilation, 46 tests, 42 rules and 126 fixtures. Windows Ruff and PowerShell execution remain the authoritative local release gate.
