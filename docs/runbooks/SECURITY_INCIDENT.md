# Runbook — ThreatLens platform security incident

1. Preserve audit/log evidence and timestamps.
2. Revoke suspected credentials/tokens and rotate affected secrets.
3. Isolate affected service exposure without deleting PostgreSQL evidence.
4. Review audit records for administrative, response, ingestion and user mutations.
5. Verify release commit/container provenance and dependency scan state.
6. Restore from a verified backup only when integrity requires it.
7. Document scope, root cause, remediation and prevention before returning to normal operation.
