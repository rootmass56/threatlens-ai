# ThreatLens AI v0.11.0 Verification

> **Historical release document.** ThreatLens v0.11.1 supersedes the dependency/vector-runtime instructions in this file. Use the current README and v0.11.1 release/verification documents for installation or deployment.


## Governed verification target

v0.11 retains all earlier deterministic, security, ATT&CK, correlation and grounded-RAG gates and adds a dedicated adaptive-runtime group.

Expected Windows governed matrix:

| Group | Tests |
|---|---:|
| Core + multi-source analytics | 49 |
| v0.4-v0.8 regressions | 23 |
| v0.9-v0.9.5 security/correctness/release | 101 |
| v0.10 grounded/hybrid RAG | 32 |
| v0.11 adaptive model runtime + UAT hardening | 28 |
| Exact Windows runtime pins | 1 |
| **Total** | **234** |

Platform-independent total: **233**.

## New v0.11 gates

`tests/test_v011_adaptive_rag.py` verifies:

- Standard/Deep benchmarked profile budgets;
- environment configuration for both models;
- routine Auto -> Standard routing;
- complex hybrid Auto -> Deep routing;
- explicit Standard/Deep overrides;
- API mode validation;
- UI/API mode propagation without direct Ollama/Chroma access;
- dual-profile health reporting;
- Deep execution;
- Deep-unavailable -> Standard fallback;
- Deep-generation-failure -> Standard regeneration;
- no Standard -> Deep silent escalation;
- pre-model prompt-injection blocking;
- persisted routing/fallback history metadata;
- sanitization of raw model error tails and transport details;
- deterministic ATT&CK technique deduplication;
- technique-specific ATT&CK/rule citation binding;
- rejection of generic-policy citations for technique-specific knowledge;
- removal of internal C# citation aliases from analyst-facing prose;
- bounded fact-versus-inference presentation;
- conservative incident-language hardening for common overclaims.

`scripts.verify_adaptive_rag` independently checks router/profile governance.

## Full Windows gate

```powershell
$env:THREATLENS_REQUIRE_RAG_READY="1"
powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

A fully ready v0.11 live gate requires:

- Chroma index ready;
- embedding model reachable;
- Standard model installed/reachable;
- Deep model installed/reachable;
- non-empty governed index;
- live structured generation smoke pass.

Default models:

```text
qwen3:4b
qwen3:8b
qwen3-embedding:0.6b
```

## Release archive gate

Generate the v0.11 manifest, create a source-only archive that excludes runtime databases, caches, secrets, vector data and nested ZIPs, then run:

```powershell
python -m scripts.verify_source_archive <archive.zip>
```

The archive is release-candidate quality only when the embedded `RELEASE_MANIFEST_v0.11.0.json` matches every releasable member with zero mismatches.
