# ThreatLens AI v0.10 Grounded RAG Architecture

## Security boundary

ThreatLens does not ask an LLM whether an attack occurred. Existing deterministic parsing, rules, risk scoring, ATT&CK mapping, semantic deduplication, entity resolution, relationship scoring and incident correlation establish the incident first. The RAG layer receives an already-authorized incident and may explain that evidence.

## Retrieval planes

**Incident evidence** is compiled from the selected persisted incident: summary, alerts, supporting events, correlation entities/relationships, registered evidence and policy-permitted analyst notes. Each item receives a stable citation identifier for that request.

**Governed knowledge** is loaded only from explicit ThreatLens documentation, governed detection YAML, and the synchronized official Enterprise ATT&CK technique store. Every source has identity, version, provenance and a deterministic document SHA-256. Chunks receive deterministic SHA-derived IDs.

## Production runtime

- vector store: ChromaDB PersistentClient;
- embeddings: configured Ollama `/api/embed` model;
- generator: configured Ollama `/api/chat` model with JSON-schema structured output;
- default LLM: `qwen3:4b`;
- default embeddings: `qwen3-embedding:0.6b`.

The local in-memory vector store and hashing embedding provider exist strictly to make security/grounding logic reproducible offline. They are not called semantic production AI.

## Query flow

```text
authenticated principal
 -> require rag:query
 -> load selected incident
 -> compile bounded authorized incident context
 -> normalize/reject hostile question patterns
 -> build deterministic query plan (ATT&CK IDs, knowledge need, incident mismatch, missing facts)
 -> retrieve exact ATT&CK/rule sources plus semantic approved knowledge
 -> reject injection-like retrieved chunks
 -> generate strict structured response
 -> validate citation IDs against authorized context
 -> calculate grounding status
 -> persist query result + audit event
 -> return through FastAPI
 -> render citations/limitations in Streamlit
```

## Failure behavior

If Chroma, embeddings or Ollama is unavailable, deterministic ThreatLens remains operational. The assistant returns explicit `llm_unavailable`, `retrieval_failed`, `disabled` or `insufficient_evidence` states instead of fabricating an answer.

## Response statuses

- `answered`
- `partially_supported`
- `insufficient_evidence`
- `out_of_scope`
- `retrieval_failed`
- `llm_unavailable`
- `disabled`

## Non-goals

The RAG layer cannot execute commands, modify detection rules, rewrite ATT&CK mappings, assign severity/risk, silently mutate case state, or perform threat-actor attribution from ordinary indicators alone.

## Claim-level grounding

The structured model response attaches citation IDs to the assessment, each key finding, and each recommended action. ThreatLens removes citation IDs that are not present in the exact authorized incident/knowledge context and computes grounding coverage across those individual claim units before returning the response.


## Advanced hybrid retrieval

The hardened retrieval path deliberately uses more than one retrieval mechanism:

1. **Incident evidence plane** — server-compiled from only the selected persisted incident.
2. **Exact governed-source plane** — requested ATT&CK IDs resolve to `attack:<ID>` sources and
   incident detections resolve to `rule:<detection_name>` sources.
3. **Semantic governed-knowledge plane** — Chroma dense retrieval supplies adjacent approved
   context when exact structured sources are insufficient.

Exact matches are merged ahead of semantic candidates, deduplicated by chunk ID, screened for
instruction-injection content and bounded before prompt assembly. The prompt assembler reserves
space across several sources so one long document cannot starve the remaining exact sources.

## ATT&CK evidence/knowledge separation

ATT&CK-focused responses can include structured `technique_explanations`. Each explanation
contains an observed-evidence field with incident-plane citations and a governed-explanation
field with knowledge-plane citations. The validator rejects cross-plane citation misuse.

## Deterministic pre-model controls

The query planner prevents unnecessary model calls when:

- a user explicitly names a different incident than the active case;
- every specifically requested malware-family / SHA-256 / threat-group fact is absent;
- threat-actor attribution is requested without direct attribution evidence;
- prompt-injection or secret-extraction language is detected.

These controls reduce hallucination risk and latency while preserving the deterministic
ThreatLens security boundary.

## Advanced hybrid retrieval hardening

The hardened v0.10 path no longer treats every question as a single dense-vector lookup. A deterministic query plan extracts explicit ATT&CK technique IDs, identifies rule sources mapped to those techniques, detects questions that require governed knowledge, and blocks explicit requests for another incident before retrieval. Retrieval then combines exact source-ID lookup with semantic retrieval. Exact retrieval is source-oriented: a long source that spans multiple chunks cannot consume the exact-match budget and starve another explicitly requested ATT&CK technique or rule.

For ATT&CK comparison questions the response contract contains structured technique explanations with two independent citation planes: persisted incident evidence and governed knowledge. The grounding validator rejects a knowledge citation used as incident evidence (and vice versa), so "what ThreatLens observed" remains distinguishable from "what ATT&CK/rule knowledge says it means."
