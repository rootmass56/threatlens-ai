# ThreatLens AI v0.10 RAG Security Threat Model

## Assets

Protected assets include incident evidence, analyst notes, evidence metadata, authentication/session state, JWT signing material, user/role data, rule governance, ATT&CK provenance, knowledge-index integrity and audit history.

## Trust boundaries

1. Browser/Streamlit -> authenticated FastAPI.
2. FastAPI -> SQLAlchemy persistence.
3. FastAPI RAG service -> local ChromaDB.
4. FastAPI RAG service -> local Ollama.
5. Approved source files/database records -> knowledge ingestion.

## Primary threats and controls

| Threat | Control |
|---|---|
| Unauthorized incident access through AI | Route authentication requires both `rag:query` and `incident:read`; incident is loaded server-side only after the principal is established |
| Privilege escalation via indexing | `rag:manage` restricted to rule engineer/administrator |
| Prompt injection in question | normalization + instruction override/secret extraction block before model invocation |
| Prompt injection in retrieved content | allowlisted sources + retrieved-text injection rejection + explicit untrusted-data delimiters |
| Hallucinated source IDs | structured per-claim output schema + citation allowlist validation; unknown IDs are discarded and lower grounding status |
| Threat actor attribution from IP/domain | deterministic attribution-evidence prerequisite; otherwise insufficient-evidence response |
| Secret extraction | system policy forbids secret/system prompt disclosure; `.env`/credentials excluded from knowledge registry and release |
| Cross-incident leakage | context compiler receives only the selected incident details; explicitly named other-incident requests are rejected before retrieval/model invocation; conversation state is not a global model memory |
| Model outage | explicit unavailable status; deterministic platform remains operational |
| Resource exhaustion / model DoS | dedicated source-IP rate-limit buckets for assistant queries and knowledge reindexing, plus bounded question/context/retrieval sizes |
| Vector/index corruption | content hashes, deterministic chunk IDs, incremental index manifest, rebuild capability |
| Silent AI activity | each query persisted with actor/model/knowledge version/latency and incident audit record |
| UI bypass of API | Streamlit RAG pages call only `ThreatLensApiClient` protected endpoints |

## Residual risk

LLMs can still produce misleading prose even with grounding controls. ThreatLens therefore displays citations and limitations, validates citation identifiers, keeps deterministic incident evidence authoritative, and treats recommendations as analyst aids rather than automatic response actions.


## Hardened citation trust model

Model-facing citation aliases are request-local convenience identifiers only. ThreatLens maps
them back to authorized real citation IDs after generation, validates the structured response a
second time, and then enforces citation planes:

- incident/evidence fields may cite only persisted incident-plane citations;
- governed-knowledge fields may cite only `KB:` sources backed by allowlisted indexed content;
- unknown aliases or real IDs are rejected and reduce grounding status.

The LLM never receives permission to convert an arbitrary string into a trusted citation.
