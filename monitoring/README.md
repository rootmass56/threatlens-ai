# Batch 7 Observability Stack

Start the normal Batch-7 platform with the `observability` profile to add Prometheus, Grafana, PostgreSQL exporter and Redis exporter.

- ThreatLens UI: http://127.0.0.1:8080
- Prometheus: http://127.0.0.1:9090
- Grafana: http://127.0.0.1:3000

The application metrics endpoint is `/internal/metrics` on the API container. It is intentionally **not** proxied by the public Nginx `/api/` boundary. Prometheus reaches it only through the internal Docker network.

Grafana credentials are read from `.env.batch7.local`. Never commit that file.
