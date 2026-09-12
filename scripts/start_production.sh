#!/usr/bin/env sh
set -eu

# Batch 7 keeps migrations/bootstrap idempotent for the single-instance local/staging
# profile. Multi-replica production deployment in Batch 8 must run migrations as a
# dedicated pre-deploy job before replicas are started.
python -m alembic upgrade head
python -m scripts.bootstrap_security

exec uvicorn api.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-10000}" \
  --proxy-headers \
  --forwarded-allow-ips="${THREATLENS_FORWARDED_ALLOW_IPS:-*}" \
  --limit-concurrency "${THREATLENS_UVICORN_LIMIT_CONCURRENCY:-200}" \
  --backlog "${THREATLENS_UVICORN_BACKLOG:-512}" \
  --timeout-keep-alive "${THREATLENS_UVICORN_KEEPALIVE_SECONDS:-5}" \
  --no-server-header \
  --no-access-log
