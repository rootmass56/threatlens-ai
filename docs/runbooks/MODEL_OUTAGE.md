# Runbook — Ollama / inference outage

Deterministic detection, incidents, hunting, case operations and evidence remain authoritative and must continue without LLM availability.

1. Check `/api/v1/rag/health` and worker logs.
2. Verify database/Redis/worker readiness separately from model readiness.
3. Do not fabricate AI answers or bypass evidence-insufficiency controls.
4. Restore inference endpoint/model availability.
5. Retry only eligible durable jobs within retry/idempotency policy.
6. Validate requested/served model, grounding and citations after recovery.
