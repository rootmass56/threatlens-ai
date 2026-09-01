# ThreatLens AI v0.7.0 Release Notes

## Complete MITRE ATT&CK awareness

- Pinned official ATT&CK v19.1 catalogs.
- Enterprise: 15 tactics, 222 techniques, 475 sub-techniques.
- Mobile: 12 tactics, 77 techniques, 47 sub-techniques.
- ICS: 12 tactics, 79 techniques, 18 sub-techniques.
- Complete STIX object and relationship persistence with raw JSON retention.

## Mapping governance

- Every Enterprise rule mapping is checked against the official catalog.
- Rule version, status, dataset, role, confidence, justification, tactic, and review outcome are
  persisted.
- Deprecated `T1060` mappings were migrated to `T1547.001` with rule version and changelog updates.
- ATT&CK v19 Defense Evasion migration aliases are handled explicitly for review consistency.

## Analyst experience

- New **MITRE ATT&CK Coverage** page.
- All-domain metrics and domain selector.
- Searchable full technique catalogs.
- Evidence-backed mapping table.
- Explicit gap table.
- Object inventory.
- CSV and Navigator JSON exports.
- In-app all-domain synchronization controls.

## Engineering

- New `attack/` domain package.
- New Alembic revision `f7b6c91a2d04`.
- Secure download and SHA-256 provenance.
- Idempotent transactional synchronization.
- Automated catalog, mapping, persistence, source, and Navigator tests.
- Updated setup and fail-fast verification suites.
