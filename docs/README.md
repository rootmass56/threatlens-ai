# ThreatLens AI documentation

This index is the authoritative entry point for the current project documentation. Files with version or batch suffixes are retained engineering history; they are not the current architecture or deployment contract.

## Current documentation

| Area | Document |
| --- | --- |
| System design | [Architecture](FINAL_ARCHITECTURE.md) |
| Product behavior | [Feature guide](FINAL_FEATURE_GUIDE.md) |
| Runtime | [Deployment and operations](FINAL_DEPLOYMENT_AND_OPERATIONS.md) |
| Security | [Security model](FINAL_SECURITY_MODEL.md) |
| AI and retrieval | [RAG / AI architecture](FINAL_RAG_AI_ARCHITECTURE.md) |
| Quality evidence | [Testing and validation](FINAL_TESTING_AND_VALIDATION.md) |
| Portfolio workflow | [Demo and interview guide](FINAL_DEMO_AND_INTERVIEW_GUIDE.md) |
| Operator support | [Troubleshooting](FINAL_TROUBLESHOOTING.md) |
| Declared constraints | [Known limitations](FINAL_LIMITATIONS.md) |

## Operational runbooks

Operational procedures live under [`runbooks/`](runbooks/). Use the deployment and operations guide before invoking a historical migration or batch-specific procedure.

Release acceptance evidence lives under [`releases/`](releases/); machine-readable release metadata lives under [`../release/`](../release/).

## Compatibility and historical material

Files with version suffixes such as `_v0.9`, `_v0.10`, or `_v0.11`, and batch-specific handoff/audit documents, describe earlier implementation milestones. They are retained only where they support governed regressions, migration evidence, or the RAG knowledge contract. Superseded generated OpenAPI snapshots and SBOMs remain available from immutable tags and Git history instead of being duplicated on current `main`.

`openapi_v0.12.0.json` remains as the React feature-parity compatibility baseline used by the current verifier. It is not a claim that the full Batch 7 API still has the v0.12 endpoint count.

The published project release is **v1.0.0**. The accepted internal source lineage remains **0.14.0** for compatibility with the frozen runtime/version contract.
