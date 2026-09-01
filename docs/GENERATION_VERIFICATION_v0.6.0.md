# v0.6.0 Release-Generation Verification

The source package was validated in a clean extracted working directory.

## Passed in the generation environment

- Python source compilation.
- 46 automated tests.
- 42/42 YAML rules valid.
- 126/126 positive, negative and boundary fixture cases passed.
- Rule lifecycle completeness: 100%.
- Fixture completeness: 100%.
- No overdue rule reviews.
- Linux regression: 9 events, 4 alerts, 1 incident, 0 quarantined.
- Multi-source regression: 22 events, 8 alerts, 2 incidents, 0 quarantined.
- ZIP structural and checksum verification.

## Windows acceptance gate

The generation environment did not provide the project Ruff executable or PowerShell runtime. The bundled fail-fast `scripts/verify.ps1` remains the authoritative Windows release gate for Ruff, Alembic and PowerShell execution.
