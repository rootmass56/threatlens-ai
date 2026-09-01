# ThreatLens AI v0.11 Adaptive AI Runtime

## Objective

v0.11 adds an auditable dual-model local AI runtime without changing the ThreatLens trust boundary. Deterministic detections, ATT&CK mappings, correlation, incident state and persisted evidence remain authoritative. The model only explains authorized evidence and governed knowledge.

## Analyst modes

- **Auto** — recommended. A deterministic router resolves the request to Standard or Deep based on query-plan complexity.
- **Standard** — forces the Standard local profile (`qwen3:4b` by default).
- **Deep Analysis** — forces the Deep local profile (`qwen3:8b` by default).

The analyst selects an investigation mode, not arbitrary model parameters. Streamlit still communicates only with the authenticated FastAPI boundary.

## Governed profiles

| Profile | Default model | Base context | Output budget | Read timeout |
|---|---|---:|---:|---:|
| Standard | `qwen3:4b` | 4096 | 900 | 360 s |
| Deep Analysis | `qwen3:8b` | 8192 | 1400 | 600 s |

The v0.10 generator may still expand the Standard per-request budget for multi-technique evidence/knowledge separation so required citation planes are not truncated.

## Deterministic Auto routing

The router never calls an LLM. It scores auditable signals including:

- evidence-vs-governed-knowledge source separation;
- number of explicit ATT&CK techniques;
- governed-knowledge requirement;
- comparative reasoning language;
- timeline/progression/cross-source reasoning language;
- large alert/event context.

The default Deep threshold is 5. Manual Standard/Deep selection overrides the Auto score.

## Fallback behavior

Deep-to-Standard fallback is enabled by default.

1. ThreatLens resolves the request to Deep.
2. If the Deep model is unavailable, Standard is selected transparently.
3. If Deep generation fails validation/runtime execution, ThreatLens can regenerate with Standard.
4. The fallback result is not trusted automatically; it passes the same citation-plane and grounding validation as any other answer.
5. Requested model, served model, fallback state and reason are returned and audited.

Standard failures do not silently escalate to Deep. This avoids unexpected high-cost execution for a request explicitly resolved to Standard.

## Observability and audit

Each assistant response carries:

- requested mode;
- resolved mode;
- requested model;
- served model;
- fallback flag/reason;
- routing reasons and complexity score;
- retrieval diagnostics;
- generation latency;
- total latency;
- grounding score;
- citations and unsupported citation IDs;
- knowledge version.

These fields are stored in the existing RAG response JSON/audit metadata. No new database schema is required in v0.11; Alembic head remains `d4a7c0e51010`.

## Security invariants retained

- prompt injection and secret-extraction patterns are rejected before generation;
- named cross-incident requests are rejected before retrieval/generation;
- absent malware/hash/threat-group fact requests are refused deterministically;
- unsupported attribution is refused before generation;
- retrieved data cannot override system policy;
- incident and governed-knowledge citation planes remain separate;
- unknown or wrong-plane citations are rejected;
- deterministic ThreatLens analytics remain authoritative.

## Knowledge-index compatibility

v0.11 changes model routing, not the governed knowledge schema. The verified v0.10 Chroma collection and its 1007-chunk ATT&CK/rule/document index can therefore be reused. A re-index is required only when governed source content, embeddings or index configuration changes.


## UAT hardening controls

The final v0.11 RC adds deterministic post-generation controls discovered during live Windows UAT:

- technique explanations are deduplicated and restricted to planned ATT&CK IDs;
- technique knowledge citations must explicitly bind to that ATT&CK ID through the official technique object or a mapped governed detection rule;
- generic policy documents cannot ground a technique-specific explanation;
- temporary prompt citation aliases are removed from prose before analyst display;
- explicit analyst-inference synthesis is supported when requested and remains separate from observed facts and governed knowledge;
- common high-risk incident overclaims are conservatively rewritten; and
- deep-to-standard fallback messages are sanitized for analysts while preserving transparent fallback state.


### v0.11 RC3 reliability hardening

- Long-running Deep failures are bounded by a guarded fallback window; ThreatLens avoids stacking another multi-minute model request after a prolonged failure.
- If both local model attempts fail, or a long Deep attempt exceeds the guarded window, ThreatLens returns a deterministic evidence-only fallback assembled from authorized incident evidence and technique-bound governed knowledge.
- Deterministic degraded responses still pass the same citation authorization, technique-binding, grounding, cross-incident, and prompt-injection controls.
