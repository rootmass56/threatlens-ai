# ThreatLens AI v0.8.0 Release Notes

## Release theme

Explainable cross-source correlation and persistent attack-graph investigation.

## Major additions

- deterministic canonical entity resolution;
- semantic alert deduplication with evidence preservation;
- explainable confidence-scored alert relationships;
- cross-source incident clustering with temporal guardrails;
- ordered ATT&CK stage progression;
- risk-aware incident titles and storylines;
- persistent graph snapshots and SHA-256 integrity;
- interactive Attack Graph Investigation page;
- correlation evidence in Current Analysis and Case Details;
- graph metrics in incident reports;
- dedicated Alembic persistence revision;
- automated correlation, entity, graph and persistence verification.

## Compatibility

- Common Event Schema remains 1.0.0.
- Governed rule catalog remains compatible with the 42-rule v0.7 mapping set.
- ATT&CK remains pinned to the verified v19.1 all-domain catalogs.
- Existing v0.7 database content is preserved.
- Linux and multi-source sample counts are unchanged.

## Honest limitations

v0.8 does not provide organization-wide identity resolution, streaming correlation, threat-actor
attribution, graph-machine learning or automatic response. Those claims require additional data,
controls and evaluation.
