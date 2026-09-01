# ThreatLens AI v0.10 — Advanced RAG/LLM Hardening Report

## Purpose

This hardening pass upgrades the v0.10 assistant from a working incident-grounded local RAG implementation into a more defensible SOC investigation subsystem. Deterministic ThreatLens analytics remain authoritative; the LLM explains authorized persisted evidence and governed security knowledge but does not decide whether an attack occurred, change incident state, or perform autonomous containment.

## Problems confirmed during UAT and source audit

1. **Official ATT&CK knowledge was not entering the production knowledge index.** `load_attack_documents()` filtered for the domain value `enterprise`, while the synchronized catalog is stored as `enterprise-attack`. The observed 47-document index therefore represented five governed project documents plus 42 detection rules, but no official Enterprise ATT&CK attack-pattern documents.
2. **Retrieval was primarily dense top-k retrieval.** Multi-part ATT&CK questions could retrieve relevant incident evidence but did not reliably force governed ATT&CK/rule knowledge into the prompt.
3. **Small top-k/context budgets could omit explicitly requested techniques.** A question asking for evidence and governed explanations for three techniques competed for only a few semantic chunks and a generic finding budget.
4. **Exact source lookup could be starved by multi-chunk documents.** A long ATT&CK source could consume several exact-result slots before another requested technique/rule was reached.
5. **Cross-incident isolation was safe but the UX was ambiguous.** A named request for another incident stayed within the current case, but the assistant could silently answer from the current incident instead of explicitly rejecting the mismatch.
6. **Missing fact questions were safe but status semantics were weak.** The model correctly said malware family/hash/actor data was unavailable, yet could still return `answered` instead of refusing before generation.
7. **Local-model reliability required a hardened model boundary.** Earlier UAT exposed long-UUID citation-copy errors, JSON grammar incompatibility, output truncation, over-produced citation lists and model/HTTP timeouts. The current adapter already uses short citation aliases, generic Ollama JSON mode, bounded output, deterministic cardinality normalization and strict post-generation validation.
8. **Hybrid source provenance was not explicit enough.** The generic answer schema did not structurally separate “what ThreatLens observed” from “what governed ATT&CK/rule knowledge says it means.”
9. **Model choice needed an evidence-based benchmark path.** Qwen3:4B is a practical local default, but final quality-profile selection should be measured against stronger local candidates rather than assumed.

## Advanced architecture implemented

### Deterministic query planning

`rag/planning.py` now derives a query plan before retrieval/generation. The plan extracts explicit ATT&CK IDs, infers relevant incident ATT&CK IDs for governed-knowledge questions, resolves mapped detection-rule source IDs, detects explicit references to another incident, detects evidence-vs-knowledge separation intent, and identifies requests for specific unsupported facts such as malware family, SHA-256 or threat-group attribution.

### Dual-channel hybrid retrieval

ThreatLens now combines:

- **exact governed-source retrieval** for planned ATT&CK IDs and incident-mapped detection rules; and
- **semantic retrieval** for additional relevant governed context.

Exact retrieval is **source-oriented, not chunk-oriented**. One representative chunk is selected per explicitly requested source so a long multi-chunk ATT&CK document cannot consume the exact-source budget and starve later requested techniques/rules.

### Correct official ATT&CK ingestion

The active Enterprise catalog lookup accepts the real persisted domain `enterprise-attack` (with legacy `enterprise` compatibility). On the submitted working database this exposes **697 active Enterprise ATT&CK attack-pattern documents**. Combined with 42 governed detection rules and five governed project documents, the hardened collector sees **744 governed documents**. A hashing/in-memory audit index produced **1,007 chunks**; the exact live Chroma chunk count can differ only if the local governed sources/database differ and must be measured after reindexing.

### Structured evidence-vs-knowledge explanations

The generated response contract now supports `technique_explanations`, where each ATT&CK technique has separate fields for:

- persisted observed evidence + incident-plane citations; and
- governed explanation + knowledge-plane citations.

The grounding validator enforces those citation planes. A knowledge citation cannot masquerade as incident evidence and an incident citation cannot satisfy governed-knowledge support.

### Stronger incident-context compilation

Incident context remains server compiled and object scoped. For technique-specific questions it prioritizes alerts matching requested ATT&CK IDs and supporting events/entities/relationships. Event snippets include safe file/domain/hash attributes when actually present, improving factual completeness without allowing the model to browse another case.

### Deterministic pre-model controls

- Explicitly naming another incident while a different case is active returns `out_of_scope` before retrieval or model execution and tells the analyst to open that case explicitly.
- Requests whose specifically named facts are wholly absent (for example malware family + SHA-256 + threat group) return `insufficient_evidence` before model execution.
- Existing threat-actor attribution refusal and prompt-injection/secret-extraction rejection remain pre-model controls.

### Hardened local Ollama adapter

The adapter keeps:

- Qwen thinking disabled for deterministic latency;
- generic Ollama JSON mode to avoid incompatible schema-grammar compilation;
- short model-facing citation aliases mapped back to real authorized IDs;
- strict Pydantic validation after generation and after alias restoration;
- deterministic deduplication/cardinality limits;
- conditional analyst recommendations rather than autonomous containment language; and
- conservative claim wording.

Advanced multi-technique evidence-vs-knowledge questions automatically receive a larger local context/output budget (8,192 context / 1,400 prediction ceiling), while ordinary incident questions retain the lighter configured profile.

### Evaluation and observability

Retrieval diagnostics now expose exact-match count, semantic count, source-kind counts, requested source IDs and missing exact source IDs. The UI shows structured ATT&CK evidence-vs-governed-knowledge sections and includes the deterministic query plan in diagnostics.

`scripts/benchmark_rag_models.py` compares local Ollama model profiles against the same persisted incident questions using response status, grounding score, citation-source mix, technique-explanation completeness, retrieval diagnostics and latency. Benchmark query/audit writes are rolled back.

## Automated verification added

The v0.10 RAG suite now contains **32 tests**. New coverage includes:

- the real `enterprise-attack` ATT&CK domain;
- exact + semantic hybrid retrieval;
- source-oriented exact retrieval under multi-chunk sources;
- query planning for exact ATT&CK/rule sources;
- explicit incident mismatch detection;
- deterministic missing malware/hash/actor fact detection;
- evidence-vs-knowledge citation-plane enforcement; and
- adaptive Ollama budget expansion for multi-technique source-separation questions.

The governed matrix is now **206 Windows tests**: 49 core/multi-source + 23 v0.4-v0.8 + 101 v0.9-v0.9.5 + 32 v0.10 RAG + 1 exact Windows runtime/dependency-pin test. **205 tests are platform-independent.**

A second offline verifier, `scripts/verify_advanced_rag.py`, independently verifies ATT&CK ingestion, exact source planning/retrieval, citation-plane grounding, cross-incident mismatch detection and missing-specific-fact detection without requiring a live LLM.

## Verification reproduced in the hardening environment

- Python compileall: PASS.
- Core/multi-source governed tests: **49 passed**.
- v0.4-v0.8 governed regressions: **23 passed**.
- v0.9-v0.9.5 security/UAT/release tests: **101 passed**.
- v0.10 advanced RAG tests: **32 passed**.
- Platform-independent governed total reproduced: **205 passed**.
- Offline grounded RAG verifier: PASS.
- Advanced hybrid RAG verifier: PASS with grounding score 1.0 and exact ATT&CK/rule retrieval.
- Package import/OpenAPI contract: PASS, 44 paths / 45 operations, canonical snapshot exact.
- Release-manifest verifier: PASS after final manifest generation.
- Repository hygiene verifier: PASS for available filesystem checks; Git tracked-file metadata is unavailable in the isolated audit environment.

The exact Windows runtime-pin test, Ruff 0.15.22 gate and live local Ollama/Chroma verification must be rerun on the project’s Windows venv because those exact local runtime dependencies/services are not available in the isolated hardening container.

## Required upgrade actions on the existing Windows working directory

After overlaying the advanced patch:

```powershell
python -m scripts.apply_advanced_rag_profile
python -m scripts.index_rag_knowledge
python -m scripts.verify_advanced_rag
python -m scripts.verify_rag_runtime --require-ready
```

The index output should now report substantially more than the old 47 documents / 88 chunks because official ATT&CK technique/sub-technique records are finally included.

Then require the full live gate:

```powershell
$env:THREATLENS_REQUIRE_RAG_READY="1"
powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

## UAT acceptance after upgrade

Repeat at least these cases:

1. Incident criticality — grounded answer with persisted evidence citations.
2. ATT&CK progression — evidence-specific citations.
3. Threat-actor identity — deterministic `insufficient_evidence` when direct attribution is absent.
4. Prompt injection/secret extraction — `out_of_scope`, not sent to model.
5. Explicit other-incident request — `out_of_scope` with instruction to open the named case; no cross-case retrieval.
6. Missing malware family/hash/threat group — deterministic `insufficient_evidence`, no model hallucination.
7. Hybrid ATT&CK explanation — every requested technique must show **both** persisted evidence citations and governed ATT&CK/rule citations.

## Model profile decision

Keep `qwen3:4b` as the lightweight default until the same evaluation is run against a stronger candidate such as `qwen3:8b`:

```powershell
python -m scripts.benchmark_rag_models --models qwen3:4b qwen3:8b --output data\rag\model_benchmark.json
```

A larger model should become the preferred quality profile only if it materially improves groundedness, source-plane completeness and structured-output reliability at acceptable latency/memory on the demonstration machine.

## Remaining honest limitation

Local CPU LLM latency is hardware-dependent and was the largest observed UAT usability constraint. The hardened architecture avoids treating latency as a correctness problem: deterministic refusals remain millisecond-scale, ordinary and hybrid generation use different budgets, model selection is benchmarkable, and the application has bounded backend/UI timeouts. A production deployment would normally use GPU acceleration and/or a dedicated model service while retaining the same RAG, authorization and grounding contracts.
