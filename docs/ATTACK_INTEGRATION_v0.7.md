# ThreatLens AI v0.7 — Complete MITRE ATT&CK Synchronization

## Scope

ThreatLens AI v0.7 synchronizes the complete official MITRE ATT&CK v19.1 STIX 2.1
catalogs for all three current ATT&CK domains:

| Domain | Tactics | Techniques | Sub-techniques |
|---|---:|---:|---:|
| Enterprise | 15 | 222 | 475 |
| Mobile | 12 | 77 | 47 |
| ICS | 12 | 79 | 18 |
| **Total domain records** | **39** | **378** | **540** |

The totals are domain records, not globally deduplicated IDs. Together, the catalogs contain 918 active technique and sub-technique records. Some technique concepts may be shared across domains.

## Critical distinction

**Catalog awareness is not detection coverage.** ThreatLens stores and exposes every object in
the pinned catalogs, but it marks an ATT&CK ID as covered only when a governed detection rule,
required telemetry, and evidence-backed mapping support the claim.

Current governed detections target Enterprise ATT&CK. Mobile and ICS are fully synchronized and
queryable as awareness catalogs, while their detection coverage remains explicitly zero until
corresponding connectors and tested rules exist.

## Synchronization flow

1. Download pinned official STIX 2.1 bundles over HTTPS from the MITRE ATT&CK data repository.
2. Restrict redirects to an allowlist of trusted hosts.
3. Validate JSON bundle structure and exact active tactic/technique/sub-technique counts.
4. Compute SHA-256 for every downloaded bundle.
5. Parse all STIX objects and relationships while preserving original raw JSON.
6. Persist catalog versions, objects, relationships, and mappings transactionally.
7. Mark previous releases inactive without deleting historical versions.
8. Resolve all governed Enterprise rule mappings against active official objects.
9. Record mapping confidence, justification, rule version, dataset, tactic consistency, and status.
10. Generate an ATT&CK Navigator layer for validated Enterprise detection coverage.

## Persisted tables

- `attack_catalog_versions`
- `attack_objects`
- `attack_relationships`
- `rule_attack_mappings`

Every non-relationship STIX object retains normalized searchable fields and its complete source
JSON. Every STIX relationship is stored separately with source, target, relationship type, and raw
JSON.

## Coverage outputs

The ATT&CK Coverage page provides:

- all-domain catalog totals;
- domain selector for Enterprise, Mobile, and ICS;
- complete searchable technique and sub-technique tables;
- full STIX object inventories;
- evidence-backed Enterprise rule mappings;
- mapping validity and tactic-review state;
- explicit unmapped catalog gaps;
- CSV exports;
- ATT&CK Navigator layer export;
- catalog release, collection ID, source timestamp, and SHA-256 provenance.

## Security and reliability controls

- pinned v19.1 sources and collection IDs;
- HTTPS-only downloads and redirect host validation;
- streamed downloads with retry and atomic replacement;
- exact catalog count assertions;
- SHA-256 provenance;
- transaction-controlled persistence;
- idempotent resynchronization;
- active/revoked/deprecated state preservation;
- no silent acceptance of invalid or retired rule mappings;
- explicit legacy tactic migration support for the ATT&CK v19 Defense Evasion split;
- automated parser, mapping, Navigator, persistence, and migration tests.
