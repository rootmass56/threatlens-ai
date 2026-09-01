# v0.5.0 Release-Generation Verification

The source package was validated from a clean extracted directory before delivery.

## Passed checks

- All Python modules compiled successfully.
- 38 automated tests passed.
- 12 YAML rules validated with zero schema issues.
- 36 of 36 positive, negative and boundary fixture cases passed.
- All six bundled source files were auto-detected by the expected connector.
- Linux regression result: 9 events, 4 alerts, 1 incident, 0 quarantined.
- Multi-source result: 22 events, 8 alerts, 2 incidents, 0 quarantined.
- Alembic upgraded a new database to `e48a7c9d2f10 (head)`.
- Alembic reported no model/migration drift.
- Package imports passed.
- Python source inspection found no syntax errors or source lines exceeding the configured 100-character limit.

## Installation acceptance gate

Run `scripts/verify.ps1` on the target Windows/Python 3.11 environment. It additionally enforces Ruff linting and Ruff formatting using the development dependency installed by `setup.ps1`.
