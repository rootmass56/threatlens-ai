# Migration: ThreatLens AI v0.9.1 to v0.9.2

v0.9.2 is a source/release-governance hotfix. There is no database migration; Alembic remains `b9f7d3c2a104`.

Remove local `ThreatLensAI_v*.zip` packages from the repository, keep releases in an external release folder, regenerate OpenAPI and the v0.9.2 manifest, and run the complete verifier.
