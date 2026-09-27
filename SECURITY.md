# ThreatLens AI Security Policy

## Release line

Batch 7 (`v0.14.x`) operationally hardens the frozen `v0.13.0` SOC capability baseline and is published as project release `v1.0.0`. The supported runtime is local Docker Compose; temporary internet-demo exposure is supervised and must not be confused with a permanently hosted SOC service.

## Security boundaries

- PostgreSQL and Redis are private Docker-network services and are not published to the host.
- The FastAPI container is not host-published; Nginx is the same-origin web/API boundary.
- The internal Prometheus endpoint is `/internal/metrics`, which is not proxied by the Nginx `/api/` location.
- Machine telemetry ingestion requires the ThreatLens ingestion credential boundary.
- User access uses Argon2id-backed accounts, signed JWT access/refresh tokens, rotation and account lockout.
- RBAC separates viewers, analysts, senior analysts, incident commanders, rule engineers and administrators.
- Response execution remains explicit-human-approval gated.
- Detection tuning proposals do not silently rewrite governed rules.
- Production secrets must be injected through environment/platform secret stores and never committed.

## Reporting a vulnerability

For the private development repository, report security findings directly to the repository owner. Do not open a public issue containing credentials, exploit payloads or sensitive test data.

## Batch-7 validation

Run `python -m ops.security.batch7_security_audit` and the Batch 7 release contract before merging source-line maintenance. CI additionally performs secret, dependency, static-code, container and CodeQL scanning.
