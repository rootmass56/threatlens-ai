# Runbook — Redis outage

ThreatLens PostgreSQL remains the durable system of record. Redis transports queued job UUIDs and worker presence.

1. Confirm API/database remain reachable.
2. Expect new AI job rows to remain durable with pending delivery when Redis is unavailable.
3. Restore Redis without deleting PostgreSQL rows.
4. Restart/verify worker presence.
5. Allow reconciliation to redeliver pending database jobs.
6. Verify each recovered job completes once and retains one final result query UUID.
7. Record the incident and recovery duration.

Do not delete queued database jobs as an outage workaround.
