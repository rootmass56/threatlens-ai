# Runbook — PostgreSQL outage

PostgreSQL is authoritative for ThreatLens operational state.

1. Treat `/health/ready` degradation as expected while PostgreSQL is unavailable.
2. Stop write-heavy UAT/load generation.
3. Restore the PostgreSQL service/managed database before attempting queue repair.
4. Verify `alembic current` equals the release head.
5. Verify incidents, audit history and durable AI jobs before restoring normal traffic.
6. If data corruption/loss is suspected, follow the backup/restore runbook instead of recreating tables manually.
