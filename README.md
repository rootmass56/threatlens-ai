# ThreatLens AI v0.14.0

**Evidence-first SOC investigation platform — final release candidate documentation**

ThreatLens AI is a production-style Security Operations Center platform for ingesting security telemetry, producing deterministic detections, correlating incidents, preserving auditable case evidence, mapping activity to MITRE ATT&CK, investigating attack graphs, running governed threat-hunting and threat-intelligence workflows, and using grounded AI to explain persisted evidence.

The current source version is **0.14.0**. The repository is progressing toward a **v1.0.0 final release only after the final Phase 10 acceptance/freeze**. Do not describe the current repository as v1.0.0 until that gate passes.

## Release lineage

- **v0.10.0 Grounded RAG Investigation Assistant** — historical milestone retained as part of the release lineage and regression contract for the grounded investigation capability.

## Authority model

ThreatLens is intentionally evidence-first:

1. Telemetry is parsed and normalized.
2. Deterministic rules, correlation, scoring, ATT&CK mappings, graph artifacts, notes and evidence are persisted.
3. Those persisted artifacts remain authoritative.
4. The RAG/LLM layer is downstream of authorized persisted evidence and governed knowledge.
5. AI output must not be treated as proof that an attack occurred.

This boundary is a core security invariant, not a presentation convention.
