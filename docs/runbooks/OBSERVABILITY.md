# Runbook — Observability

## Surfaces

- API/worker logs: Docker stdout/stderr, structured JSON in Batch-7 Compose.
- API internal metrics: `api:10000/internal/metrics` on the private Docker network.
- Prometheus: `http://127.0.0.1:9090` with the observability profile.
- Grafana: `http://127.0.0.1:3000` with credentials from `.env.batch7.local`.
- Protected JSON operational view: `/api/v1/system/observability` for authorized users.

## First checks during an incident

1. Read `/api/v1/health/ready`.
2. Inspect request/error rate and p95 latency.
3. Inspect AI queue pending/workers.
4. Inspect PostgreSQL connection/activity metrics.
5. Inspect Redis memory/reachability.
6. Correlate application logs by `request_id`, incident/job UUID and component.

Do not paste credentials or bearer tokens into dashboards or logs.
