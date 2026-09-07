# Runbook — Deployment / Rollback boundary

Batch 7 prepares deployment discipline; final cloud deployment is Batch 8.

1. Build immutable images from a reviewed Git commit.
2. Generate/retain SBOM and security gate evidence.
3. Take a verified database backup before schema migration.
4. Run Alembic once as a pre-deploy migration job.
5. Deploy API/worker/frontend from the same release commit.
6. Run readiness and smoke UAT.
7. Roll application images back only when schema compatibility is understood. Database downgrade is never automatic during incident response.
8. Preserve release/tag history; never rewrite a frozen tag.
