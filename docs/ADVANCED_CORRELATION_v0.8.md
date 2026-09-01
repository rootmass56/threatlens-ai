# ThreatLens AI v0.8 — Advanced Correlation Architecture

## Purpose

The v0.8 engine converts independent alerts into explainable incident storylines without using
opaque machine-learning clustering. Every decision is deterministic, versioned, thresholded and
supported by persisted evidence.

## Processing stages

1. **Input preservation** — All rule alerts and linked events remain unchanged.
2. **Semantic deduplication** — Near-time alerts with matching detection and entity context are
   grouped for correlation only. Representative records retain duplicate alert identifiers.
3. **Entity resolution** — Values are normalized into canonical IP, host, user, process, domain,
   URL, file and hash entities.
4. **Relationship scoring** — Each candidate alert pair receives a confidence score and explicit
   reasons.
5. **Cluster eligibility** — Only relationships meeting policy thresholds can connect incidents.
6. **Temporal guardrails** — Maximum incident spans prevent unrelated long-range activity from
   merging.
7. **ATT&CK ordering** — Rule mappings are translated into an ordered tactic progression.
8. **Incident synthesis** — Connected alerts produce a risk-aware title, summary, stage path,
   storyline and graph metrics.
9. **Graph construction** — Incident, alert, entity, technique and tactic layers are generated.
10. **Transactional persistence** — Correlation output is committed with the analysis or rolled
    back as one unit.

## Relationship evidence

A scored relationship may use:

- shared canonical entities;
- source and destination infrastructure;
- user or host continuity;
- process, domain, URL, file or hash continuity;
- temporal proximity;
- corroboration from different telemetry datasets;
- ordered ATT&CK progression;
- compatible detection semantics.

Each persisted relationship stores confidence, relationship type, shared entities, reasons,
time delta, evidence alert identifiers and whether it was eligible to join an incident.

## Deduplication policy

Deduplication reduces graph noise but never deletes raw evidence. The output distinguishes:

- input alert count;
- representative alert count;
- deduplicated alert count;
- duplicate-group count.

The established multi-source demonstration contains eight original alerts, seven representative
alerts and one semantic duplicate. All eight alerts remain persisted and reportable.

## Entity resolution policy

Canonicalization is conservative. It normalizes case, whitespace and well-defined representations
without inferring real-world identity ownership. A hostname and an IP address are separate entities
unless the supplied telemetry explicitly supports both on the same evidence path.

Entity records include:

- stable entity UUID and deterministic entity key;
- type, canonical value and display value;
- confidence and aliases;
- source datasets;
- alert and event provenance;
- first-seen and last-seen timestamps;
- incident associations.

## ATT&CK stage progression

The engine uses official rule mappings and a versioned tactic order. It also supports v19 taxonomy
labels such as Stealth and Defense Impairment. Stage progression is evidence presentation, not a
claim that every intermediate adversary action was observed.

## Guardrails

- no probabilistic attribution;
- no hidden AI decision path;
- no deletion of original alert evidence;
- no automatic case closure;
- no universal ATT&CK detection claim;
- no cross-analysis entity joining in v0.8;
- deterministic policy values included in each graph snapshot.

## Validated sample outcomes

### Linux authentication

- 9 events
- 4 alerts
- 1 incident
- progression includes Credential Access and Privilege Escalation

### Multi-source demonstration

- 22 events
- 8 original alerts
- 7 representative alerts
- 1 semantic duplicate
- 2 multi-source incidents
- 2 multi-stage incidents
- at least 10 resolved entities
- 15 scored relationships
- 30 graph nodes
- 62 graph edges
