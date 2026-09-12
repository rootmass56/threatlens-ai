# Runbook — Start / Stop Batch 7

## Start

1. Ensure Docker Desktop and Ollama are available.
2. Run `scripts/bootstrap_batch7_env.ps1` once.
3. If preserving Batch-6 operational data, use `scripts/MIGRATE_BATCH6_DATA_TO_BATCH7.ps1` before normal startup.
4. Start core platform with `scripts/start_batch7_stack.ps1`.
5. Start core + observability with `scripts/start_batch7_stack.ps1 -Observability`.
6. Require `/api/v1/health/ready` to return `status=ready`, database reachable, Redis reachable and at least one worker.

## Stop

Run `scripts/stop_batch7_stack.ps1`.

Never use `-RemoveVolumes` during ordinary shutdown. Volume removal is destructive and requires a verified backup.
