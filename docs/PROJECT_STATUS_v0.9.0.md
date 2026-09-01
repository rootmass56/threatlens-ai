# ThreatLens AI Project Status — v0.9.0

## Completed releases

- v0.1–v0.3: core analytics, persistence and case management
- v0.4: common schema and external YAML detection engine
- v0.5: Linux, Windows, Sysmon, Suricata and Zeek ingestion
- v0.6: governed 42-rule/126-fixture detection catalogue
- v0.7: complete ATT&CK v19.1 all-domain awareness and coverage analysis
- v0.8: entity resolution, semantic deduplication, advanced correlation and persistent attack graphs
- v0.9: FastAPI service boundary, authentication, RBAC, user/session administration and API security

## v0.9 verified product boundary

- 41 registered FastAPI routes, 40 unique paths
- six persistent system roles
- explicit permission union and object-level case checks
- protected OpenAPI contract
- API-backed Streamlit page service
- persistent account, token and login-attempt state
- authenticated report generation
- exact Alembic head `b9f7d3c2a104`
- 97 governed Windows automated tests, including exact runtime pin validation

## Current maturity

The cybersecurity analytics and investigation core is advanced and stable. The product now has a defensible security/API boundary. It is still an industrial demonstration rather than a production SIEM because grounded RAG, PostgreSQL/Docker operations and formal final security/performance evaluation remain.

## Mandatory remaining releases

- v0.10: grounded local RAG analyst assistant
- v0.11: PostgreSQL, Docker Compose and operations
- v1.0: formal security, performance, coverage, UAT and final evidence package
