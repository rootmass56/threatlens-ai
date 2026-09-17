# ThreatLens AI documentation

Start with the **final documentation set** below. Older versioned documents are retained only as engineering history and should not be treated as the current architecture or deployment contract.

## Current documentation

- [Final architecture](FINAL_ARCHITECTURE.md)
- [Deployment and operations](FINAL_DEPLOYMENT_AND_OPERATIONS.md)
- [Security model](FINAL_SECURITY_MODEL.md)
- [RAG / AI architecture](FINAL_RAG_AI_ARCHITECTURE.md)
- [Testing and validation](FINAL_TESTING_AND_VALIDATION.md)
- [Feature guide](FINAL_FEATURE_GUIDE.md)
- [Demo and interview guide](FINAL_DEMO_AND_INTERVIEW_GUIDE.md)
- [Troubleshooting](FINAL_TROUBLESHOOTING.md)
- [Limitations](FINAL_LIMITATIONS.md)

## Operational runbooks

Operational procedures live under [`runbooks/`](runbooks/). Use the final deployment/operations guide as the entry point before invoking historical migration or batch-specific procedures.

## Historical material

Files with version suffixes such as `_v0.9`, `_v0.10` or `_v0.11`, and batch-specific handoff/audit documents, describe earlier implementation milestones. They remain in Git history for traceability but are not the current release contract.

The published project release is **v1.0.0**. The accepted internal source lineage remains **0.14.0** for compatibility with the frozen runtime/version contract.
