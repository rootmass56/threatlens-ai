# ThreatLens AI v0.12.0 LLM and Embedding Strategy

## Authority boundary

ThreatLens does not ask an LLM whether an attack happened. Detection rules, correlation, risk, ATT&CK mappings and persisted incident evidence remain deterministic. The LLM receives only bounded server-compiled incident context plus allowlisted knowledge, and generated claims are subjected to citation/grounding validation.

## v0.12 model profiles

### Standard

- Default: `qwen3.5:4b`
- Purpose: routine SOC explanation, evidence summaries, short investigation questions.
- Benefit: compact deployment footprint and lower latency.

### Deep Analysis

- Default: `qwen3.5:9b`
- Purpose: multi-technique reasoning, evidence/knowledge separation, more complex incident explanation.
- Trigger: explicit analyst selection or deterministic complexity routing.
- Failure behavior: transparent fallback to Standard, then deterministic evidence-only degradation if necessary.

### Embeddings

- Default: `qwen3-embedding:0.6b`
- Dimensions: 1024
- Purpose: semantic retrieval over governed ThreatLens/ATT&CK knowledge.
- Production storage: PostgreSQL `pgvector`.
- Local storage: ThreatLens SQLite exact-cosine vector store.

## Why Qwen3.5 for generation

At the v0.12 design date, Qwen3.5 provides compact 4B and 9B Ollama variants, while newer Qwen3.6/Qwen3.8 offerings are materially larger. ThreatLens prioritizes a model pair that can realistically run on modest GPU infrastructure while still preserving a distinct Standard/Deep architecture.

The model names remain environment-controlled. Upgrading a model never bypasses the governed evaluation gate: structured-output behavior, citation discipline, latency, fallback and grounding must be benchmarked before a new model becomes a frozen default.

## Production inference choices

### Preferred for a serious deployed demo

Run the 4B and 9B models on a dedicated GPU inference host exposing an Ollama-compatible HTTPS endpoint. Set:

```text
THREATLENS_OLLAMA_URL=https://<inference-host>
THREATLENS_OLLAMA_API_KEY=<secret>
THREATLENS_RAG_STANDARD_LLM_MODEL=qwen3.5:4b
THREATLENS_RAG_DEEP_LLM_MODEL=qwen3.5:9b
```

The FastAPI backend is the only component allowed to hold this secret. It must never be exposed as a Vite `VITE_*` variable.

### Ollama Cloud-compatible fallback

Ollama also provides API-key-authenticated cloud access. Cloud model availability can differ from locally tagged 4B/9B models, so production environment values may be changed without code changes. If Standard and Deep resolve to the same hosted model, ThreatLens still applies different routing/context/output budgets, but the deployment should be documented as a single-model hosted profile rather than claiming two different model weights.

## Embedding deployment warning

A production query needs an embedding for each user question, so storing precomputed vectors in pgvector is not sufficient by itself. The deployment must provide a reachable embedding service for `qwen3-embedding:0.6b` (or a separately evaluated replacement). ThreatLens must not silently switch to the hashing test embedding in production.
