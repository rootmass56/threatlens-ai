# ThreatLens AI v0.10.0 Release Notes

> **Historical release document.** ThreatLens v0.11.1 supersedes the dependency/vector-runtime instructions in this file. Use the current README and v0.11.1 release/verification documents for installation or deployment.


v0.10.0 introduces the Grounded RAG Investigation Assistant over the approved v0.9.5 deterministic platform.

Major additions include governed knowledge ingestion, deterministic chunk identities, ChromaDB persistence, Ollama Qwen generation/embeddings, incident-context compilation, citation validation, prompt-injection defenses, attribution refusal, RAG-specific RBAC, assistant query history/audit persistence, protected FastAPI RAG operations, a Case Details AI Assistant tab, and an AI Knowledge Administration page.

The release adds Alembic revision `d4a7c0e51010` and pins `chromadb==1.5.9`. Default external models are `qwen3:4b` and `qwen3-embedding:0.6b`.

No AI output changes a deterministic detection, ATT&CK mapping, risk score, correlation relationship or incident state automatically. Live external model/vector readiness can be required explicitly during verification; otherwise offline RAG security/grounding verification remains mandatory and deterministic analytics stay available during model outage.
