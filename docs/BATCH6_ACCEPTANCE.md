# Batch 6 Acceptance Matrix

| Workstream | Acceptance evidence |
|---|---|
| 6A | authenticated source creation; one-time key; durable receipt; duplicate client-event id handled; connector parse failure retained; source rate/CIDR enforcement |
| 6B | feed + IOC import; STIX parser; provenance/TLP/confidence; expiry/revocation; analysis enrichment; enrichment-only flag |
| 6C | structured hunt over events/entities/alerts; safe filters; saved hunts; execution history |
| 6D | case profile; tasks; handoffs; evidence custody chronology; audit events |
| 6E | playbook request/approve/complete state machine; no unapproved execution; result + rollback note persisted |
| 6F | analyst feedback; rule effectiveness; tuning proposal/review; no silent runtime mutation |
| 6G | Entra connector + 4 governed rules + 12 fixtures |
| 6H | graph node/edge evidence views; path query; entity timeline; global search |
| Security | RBAC for human routes; machine-key boundary for ingest; audit coverage; safe validation/error behavior |
| Data | Alembic head `f6a6c0b60001`; 15 new persistent advanced-SOC tables |
| Regression | Batch-6 target suite + Batch-5 durable AI/security gate + frontend build/container smoke |
