# Batch 7 PostgreSQL / pgvector performance discipline

The `b7f1c2d30001` migration adds composite indexes for durable AI recovery, audit views, ingestion, hunts, response ledgers and task queues. `performance_audit.py` reports table size, sequential/index scan usage and unused indexes from PostgreSQL statistics.

Run inside the API container after realistic UAT/load activity so the statistics are meaningful:

`python -m ops.db.performance_audit`

Do not remove indexes solely because `idx_scan` is zero in a short-lived test database.
