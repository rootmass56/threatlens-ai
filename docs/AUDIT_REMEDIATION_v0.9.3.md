# ThreatLens AI v0.9.3 Deep-Audit Remediation

This release closes confirmed problems reproduced against the exact v0.9.2 tagged ZIP.

| Finding | v0.9.3 control |
|---|---|
| Omitted PATCH assignee interpreted as change | Pydantic field-set aware workflow merge |
| Nonexistent/ineligible case assignee accepted | Active investigator-role validation |
| Raw-byte duplicate identity ignored parser semantics | Persisted semantic analysis fingerprint/context |
| Expired lockout retained threshold count | Expiry resets timed failure window |
| Login exposed locked/disabled state | Generic external 401 + precise internal audit reason |
| Raw path rate-limit buckets grew/bypassed | Fixed policy buckets + bounded cardinality |
| Same-second reports collided | UUID-suffixed filenames |
| API report temp files persisted | Guaranteed unlink after reading |
| Sync CPU analytics inside async upload | Threadpool offload |
| Partial dependency reproducibility | Exact direct runtime/dev pins |
| Arbitrary ZIP could evade manifest | Any tracked/nested ZIP rejected |
| Stale UI/personal defaults | Dynamic catalogue label + neutral analyst default |

The release intentionally does not add RAG, PostgreSQL, Docker, distributed rate limiting or production queueing; those remain controlled later milestones.
