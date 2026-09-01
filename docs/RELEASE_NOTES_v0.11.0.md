# ThreatLens AI v0.11.0 Release Notes

> **Historical release document.** ThreatLens v0.11.1 supersedes the dependency/vector-runtime instructions in this file. Use the current README and v0.11.1 release/verification documents for installation or deployment.


## Adaptive dual-model investigation runtime

ThreatLens v0.11 extends the verified v0.10 grounded RAG assistant with deterministic model routing and two governed local inference profiles:

- Standard: `qwen3:4b`;
- Deep Analysis: `qwen3:8b`.

Analysts choose Auto, Standard or Deep Analysis. Auto is resolved by deterministic query-plan complexity signals rather than by another model. Both inference profiles share the same server-compiled incident evidence, governed ATT&CK/rule/document knowledge, citation-plane enforcement, injection controls, structured validation and final grounding checks.

## Benchmarked Deep profile

The Deep profile uses the configuration established during v0.10 model evaluation:

- 8192 context window;
- 1400 output-token budget;
- 600-second model read timeout.

The larger output budget is important for reliable structured 8B generation. The Standard profile retains its lower-cost base configuration and may expand its per-request budget for required multi-technique source separation.

## Transparent fallback

When a request resolves to Deep and the Deep model is unavailable or generation fails, ThreatLens may regenerate with Standard. The response exposes requested/served model and fallback state; the regenerated answer must independently pass the existing grounding/citation validators before it can be returned.

## Audit and observability

No schema migration is required. Existing RAG response JSON/audit records now include routing mode, model selection, fallback metadata, routing score/reasons and generation latency. The existing `llm_model` persistence field continues to represent the model that actually served the completed answer.

## Compatibility

- Alembic head remains `d4a7c0e51010`.
- The v0.10 governed knowledge index schema remains compatible.
- Existing verified 1007-chunk Chroma state can be reused.
- API remains 44 paths / 45 operations; the assistant request body gains an enum `analysis_mode` field.
- Deterministic analytics and all v0.10 RAG trust-boundary controls remain authoritative.

## RC UAT hardening

Live Windows UAT of Auto, Standard, Deep and forced Deep-to-Standard fallback added a final deterministic hardening layer: technique objects are deduplicated and restricted to planned ATT&CK IDs; technique knowledge citations must explicitly bind to the same ATT&CK ID through an official ATT&CK object or mapped detection rule; internal short prompt aliases are removed from prose; explicit analyst inference is supported when requested; common high-risk incident overclaims are conservatively rewritten; and analyst-facing fallback messages no longer expose local model transport details.

The governed v0.11 test group is now 28 tests, for **233 platform-independent tests / 234 Windows tests** overall.


### v0.11 RC3 reliability hardening

- Long-running Deep failures are bounded by a guarded fallback window; ThreatLens avoids stacking another multi-minute model request after a prolonged failure.
- If both local model attempts fail, or a long Deep attempt exceeds the guarded window, ThreatLens returns a deterministic evidence-only fallback assembled from authorized incident evidence and technique-bound governed knowledge.
- Deterministic degraded responses still pass the same citation authorization, technique-binding, grounding, cross-incident, and prompt-injection controls.
