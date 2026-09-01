# ATT&CK Runtime Catalogs

ThreatLens AI v0.7 synchronizes the complete official MITRE ATT&CK v19.1 STIX 2.1
collections for all current ATT&CK domains:

- Enterprise: 15 tactics, 222 techniques, 475 sub-techniques
- Mobile: 12 tactics, 77 techniques, 47 sub-techniques
- ICS: 12 tactics, 79 techniques, 18 sub-techniques

The downloaded bundles and their metadata are runtime files and are intentionally
excluded from Git and release ZIPs. `scripts/setup.ps1` downloads the pinned official
files, validates exact counts, fingerprints them with SHA-256, applies the database
migration, and persists every STIX object and relationship.

Catalog awareness is not detection coverage. Current ThreatLens telemetry and governed
rules target Enterprise ATT&CK. Mobile and ICS catalogs are synchronized and queryable,
but are displayed as catalog-awareness-only until corresponding telemetry and validated
rules are implemented.
