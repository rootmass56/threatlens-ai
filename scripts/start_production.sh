#!/usr/bin/env sh
set -eu

# Render Free does not support pre-deploy commands. For the single-instance
# ThreatLens demo deployment, apply idempotent migrations and bootstrap roles/admin
# before starting the API. Paid/scaled deployments should move migrations to a
# pre-deploy/CI migration job to avoid concurrent migration runners.
python -m alembic upgrade head
python -m scripts.bootstrap_security

exec uvicorn api.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-10000}" \
  --proxy-headers \
  --forwarded-allow-ips='*'
