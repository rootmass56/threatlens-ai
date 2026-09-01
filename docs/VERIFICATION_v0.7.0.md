# ThreatLens AI v0.7.0 Verification Evidence

## Required Windows command

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

## Required catalog assertions

| Domain | Tactics | Techniques | Sub-techniques |
|---|---:|---:|---:|
| Enterprise | 15 | 222 | 475 |
| Mobile | 12 | 77 | 47 |
| ICS | 12 | 79 | 18 |

All synchronized bundles must use version `19.1`, match their pinned collection IDs and source timestamps, match their persisted SHA-256 fingerprints, and be present in the database. The combined acceptance target is 39 tactics, 378 techniques, 540 sub-techniques, and 918 technique/sub-technique domain records.

## Required mapping assertions

- All governed Enterprise rule ATT&CK IDs resolve to active official objects.
- Every mapping includes a non-empty justification.
- Every declared tactic is consistent or covered by the documented v19 migration alias.
- Persisted mapping count matches the in-memory validated catalogue.
- Navigator layer contains every unique valid mapped ATT&CK ID and no invalid ID.

## Existing regressions retained

- 42 governed rules.
- 126 positive, negative, and boundary fixtures.
- Linux: 9 events, 4 alerts, 1 incident, 0 quarantined.
- Multi-source: 22 events, 8 alerts, 2 incidents, 0 quarantined.


## Automated test target

The complete Windows environment must report **59 passed**. The packaging environment runs 58 tests because the pinned Streamlit/Starlette runtime test requires the project's Windows dependency environment.
