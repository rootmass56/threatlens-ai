# ThreatLens AI v0.10.0 Verification

> **Historical release document.** ThreatLens v0.11.1 supersedes the dependency/vector-runtime instructions in this file. Use the current README and v0.11.1 release/verification documents for installation or deployment.


Primary Windows gate:

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

Expected governed matrix: **206 tests** = 49 core/multi-source + 23 v0.4-v0.8 + 101 v0.9-v0.9.5 + 32 v0.10 RAG + 1 exact runtime/dependency pin.

Mandatory gates include compilation, Ruff lint/format, governed tests, Alembic no-drift/head `d4a7c0e51010`, 42 rules/126 fixtures, ATT&CK v19.1 all domains, connectors, advanced correlation/graphs, API security, offline grounded-RAG verification, Linux 9/4/1/0, five-source 22/8/2/0, canonical OpenAPI 44/45, repository hygiene and v0.10 release-manifest integrity.

Live external end-to-end gate (required for final release approval):

```powershell
$env:THREATLENS_REQUIRE_RAG_READY = "1"
.\scripts\verify.ps1
```

The live gate performs real Ollama embedding, Chroma retrieval, and structured Ollama generation. A final release archive must also pass `python -m scripts.verify_source_archive <zip>` and be independently audited before tagging/final distribution.


Additional advanced-RAG regressions verify the real Enterprise ATT&CK catalog domain,
exact-source hybrid retrieval, query-plan construction, named cross-incident mismatch
detection, deterministic refusal of wholly missing malware/hash/actor facts, strict
incident-vs-knowledge citation planes, and stable ATT&CK-ID extraction.

The full v0.10 gate also runs `python -m scripts.verify_advanced_rag`, which independently verifies Enterprise ATT&CK ingestion under the real `enterprise-attack` domain, query planning, source-oriented exact ATT&CK/rule retrieval, evidence-vs-knowledge citation-plane enforcement, explicit cross-incident mismatch detection and deterministic missing-fact detection without requiring a live LLM.
