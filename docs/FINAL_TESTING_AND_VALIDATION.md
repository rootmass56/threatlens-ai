# ThreatLens AI — Final Testing and Validation

## Validation philosophy

ThreatLens uses release gates that separate:

- deterministic product correctness;
- runtime/infrastructure reliability;
- AI/RAG security;
- concurrency/performance;
- demonstration quality;
- documentation/release integrity.

A passing presentation or demo is not a substitute for deterministic product tests, and an LLM response is not a substitute for persisted evidence.

## Accepted validation layers

### Deterministic SOC UAT

End-to-end UAT covered:

- heterogeneous telemetry parsing;
- normalized event persistence;
- deterministic alerts;
- incident correlation;
- quarantine/negative-input behavior;
- ATT&CK context;
- attack graph artifacts;
- case evidence and auditability.

The accepted Golden Demo reference analysis is:

| Metric | Accepted reference value |
|---|---:|
| Normalized events | 10 |
| Alerts | 8 |
| Incidents | 5 |
| Quarantined | 0 |

These values describe one frozen reference dataset only.

### Negative-input behavior

Malformed/invalid inputs were exercised through controlled UAT so that invalid data follows quarantine/error contracts rather than being silently accepted as valid telemetry.

### Reliability and recovery

Infrastructure recovery validation included controlled disturbance/recovery of core services and verification that durable state remained intact.

The release process explicitly avoids using destructive volume deletion as a recovery shortcut.

### Concurrency and idempotency

A concurrency defect in AI job creation was identified during testing and repaired using transaction/savepoint handling around the database uniqueness boundary.

The accepted repaired behavior demonstrated concurrent identical idempotent requests without generic HTTP 500 responses and with one durable logical job plus safe replays.

This history is important: the project does not claim that concurrency was correct merely because sequential tests passed.

### AI / RAG adversarial validation

Adversarial testing covered scenarios including:

- prompt injection;
- secret-extraction attempts;
- cross-incident isolation;
- unsupported attribution;
- citation spoofing;
- overclaim hardening;
- invalid/failed generation;
- deterministic fallback.

The authority invariant remained unchanged: deterministic persisted evidence is authoritative.

### Runtime health

The canonical strict local acceptance command is:

```powershell
.\CHECK_THREATLENS.ps1 -RequireObservability -RequireAI
```

It validates core services, frontend/API endpoints, observability, Ollama availability and grounded-RAG live readiness.

### RAG baseline

Accepted runtime observations include:

- vector backend: pgvector;
- embedding dimensions: 1024;
- indexed governed-knowledge baseline: 1007 chunks;
- Standard model: `qwen3.5:4b`;
- Deep model: `qwen3.5:9b`;
- embedding model: `qwen3-embedding:0.6b`.

The exact chunk count is evidence from the accepted corpus state, not a forever-fixed constant.

### Public showcase

The static public showcase is distinct from the authenticated SOC console. Its purpose is portfolio/recruiter presentation without exposing the operational backend.

### Temporary internet demo

The Phase 9 workflow validated:

- HTTPS public access through a temporary Quick Tunnel;
- frontend security headers;
- same-origin API behavior;
- unauthenticated boundary;
- authenticated browser access;
- controlled shutdown/revocation;
- local runtime remaining healthy after revocation.

This does not imply permanent public hosting.

### Presentation acceptance

Presentation validation covered:

- final presentation documents;
- architecture/system diagrams;
- fourteen presentation screenshots;
- runtime/RAG readiness at the time of freeze;
- clean Git state.

## Historical test counts

Older versioned documents may contain exact historical test counts, API-operation counts or rule counts.

Do **not** reuse those numbers as current claims without re-deriving them from the current accepted source. Final documentation therefore emphasizes accepted gate outcomes and stable architectural contracts instead of copying stale counts.

## Evidence handling

Release-gate evidence lives outside the immutable source tree under the configured runtime evidence root.

Evidence receipts should contain hashes, status and non-secret validation details. They must not contain passwords, bearer tokens, refresh tokens or private keys.

## Final release acceptance

Phase 10 completed the final v1.0.0 acceptance and protected release.

The correct post-release description is:

- accepted internal source lineage: 0.14.0;
- published project release: v1.0.0;
- protected release PR: #18;
- release commit: `cd6994b560ac4ca079d23033d52b7593f260dbea`;
- release tree: `1e73c7ed2a7db153b2e53e186c4f59b917be45cf`;
- current `main` may contain later protected repository-presentation maintenance without changing the immutable release tag.
