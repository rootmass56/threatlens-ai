# Runbook — Credential rotation

Rotate credentials through the deployment secret store or `.env.batch7.local` only for local development.

Priority secrets:

- JWT signing secret;
- PostgreSQL password;
- Redis password;
- bootstrap administrator secret (fresh environments only);
- machine-ingestion keys;
- Grafana administrator password;
- remote inference/API credentials.

Rotation requiring service URL changes must be coordinated so applications and backing services agree. Never commit rotated credentials to Git.
