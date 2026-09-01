# ThreatLens AI ATT&CK Coverage Policy

## Purpose

ThreatLens AI uses MITRE ATT&CK as a versioned knowledge catalog and as a controlled taxonomy
for evidence-backed detection mappings. The platform deliberately distinguishes complete catalog
awareness from actual detection coverage.

## Complete catalog awareness

Version 0.7 synchronizes the complete pinned ATT&CK v19.1 STIX 2.1 collections for:

- Enterprise ATT&CK: 15 tactics, 222 techniques, 475 sub-techniques;
- Mobile ATT&CK: 12 tactics, 77 techniques, 47 sub-techniques;
- ICS ATT&CK: 12 tactics, 79 techniques, 18 sub-techniques.

This equals 918 active technique and sub-technique records across the three domain catalogs.
Domain totals are not globally deduplicated because an ATT&CK ID may appear in more than one
domain.

Every STIX object and relationship is retained with source release, collection identity, source
modified timestamp, SHA-256 provenance, active/revoked/deprecated state, and raw JSON.

## Detection coverage

An ATT&CK ID is marked as detected or covered only when all of the following are true:

1. A governed ThreatLens detection rule declares the mapping.
2. The ID resolves to an active object in the pinned official catalog.
3. The declared tactic is consistent with the official object or a documented migration alias.
4. A non-empty mapping justification explains the evidence relationship.
5. The required telemetry is supported by an enabled connector and parser.
6. Positive, negative, and boundary fixtures pass for the rule.

Current governed detections target Enterprise ATT&CK. Mobile and ICS are synchronized and fully
queryable, but their detection coverage remains explicitly zero until domain-specific telemetry
and validated rules are implemented.

## Prohibited claims

ThreatLens documentation, dashboards, reports, and presentations must not state that:

- every ATT&CK technique is detectable;
- catalog synchronization equals sensor coverage;
- one rule validates an entire tactic;
- a missing mapping means an ATT&CK object is absent;
- AI-generated text creates or validates a detection mapping.

## Required outputs

The platform must expose:

- full per-domain catalog inventories;
- evidence-backed mappings;
- invalid or retired mapping findings;
- explicit unmapped gaps;
- telemetry requirements;
- source release and SHA-256 provenance;
- ATT&CK Navigator export for validated Enterprise rule coverage.
