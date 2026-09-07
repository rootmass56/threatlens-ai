# Runbook — Worker crash / lease recovery

1. Verify the affected durable job is `running`, identify worker ID and lease expiry.
2. Do not manually mark the job succeeded/failed while its lease is active.
3. Restore or start a worker.
4. After the stale lease/recovery interval, verify the database recovery path requeues within retry budget.
5. Verify `attempts` does not exceed configured maximum.
6. Verify one final persisted RAG result and no duplicate completed investigation query.
