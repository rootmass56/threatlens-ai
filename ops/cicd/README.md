# Batch 7 CI/CD and deployment gates

Batch 7 prepares an auditable delivery pipeline but deliberately does **not** perform the final cloud deployment; that is Batch 8.

The CI pipeline gates Python tests, reviewed dependency/SBOM checks, Ruff, frontend type/build/audit, secret scanning and container vulnerability scanning. CodeQL runs on pushes/PRs and weekly. A manual GHCR workflow can publish immutable API/frontend images by Git commit SHA.

Production/staging deployment must consume immutable image digests or SHA-tagged images and must run Alembic migration as a controlled pre-deploy step before horizontally scaling API replicas.
