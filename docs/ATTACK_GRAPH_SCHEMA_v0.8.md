# ThreatLens AI Attack Graph Schema v1.0

## Envelope

Every exported and persisted graph uses:

```json
{
  "schema": "threatlens-attack-graph-1.0",
  "correlation_version": "0.8.0",
  "policy": {},
  "metrics": {},
  "nodes": [],
  "edges": []
}
```

The canonical compact JSON representation is hashed with SHA-256. The hash is stored with the
snapshot and verified during tests.

## Node layers

| Layer | Purpose |
|---|---|
| incident | Correlated SOC investigation case |
| alert | Original governed-rule finding |
| entity | Canonical observable or identity context |
| technique | ATT&CK technique or sub-technique |
| tactic | Ordered ATT&CK stage |

Common node fields include `node_id`, `node_type`, `label`, `incident_ids`, `metadata`, `x` and
`y`. Coordinates provide a deterministic initial layout and can be replaced by a presentation
layer without altering evidence identity.

## Edge types

| Edge | Meaning |
|---|---|
| contains_alert | Incident contains an original alert |
| observed_entity | Alert or incident is supported by an entity |
| maps_to_technique | Alert maps to an evidence-backed ATT&CK ID |
| belongs_to_tactic | Technique is presented under an ATT&CK stage |
| correlated_with | Scored alert relationship |
| semantic_duplicate | Alert evidence was grouped for correlation noise reduction |

Edges may contain confidence, reasons, shared entities, time delta, cluster eligibility and
incident identifiers.

## Integrity rules

- every edge source and target must reference an existing node;
- every incident graph must retain its original alert nodes;
- semantic duplicate edges must preserve the duplicate alert IDs;
- graph schema and correlation version are mandatory;
- node and edge counts must equal persisted snapshot counts;
- graph SHA-256 must match the canonical payload;
- graph exports must not contain database secrets or raw uploaded file content.

## Export formats

The application exposes:

- full attack graph JSON;
- graph-node CSV;
- graph-edge CSV;
- resolved-entity CSV;
- scored-relationship CSV.

The JSON export is the authoritative machine-readable representation. CSV exports are analyst
convenience views.
