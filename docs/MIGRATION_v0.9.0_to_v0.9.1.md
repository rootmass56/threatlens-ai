# Migration: ThreatLens AI v0.9.0 to v0.9.1

v0.9.1 is a source/configuration/test hotfix. **There is no new Alembic migration.** The database head remains `b9f7d3c2a104`.

## Upgrade steps

1. Back up the v0.9.0 repository and runtime `.env`/database outside Git.
2. Apply the v0.9.1 source tree.
3. Run `scripts/setup.ps1` so `httpx2==2.7.0` and the remaining pinned dependencies are installed.
4. If `THREATLENS_JWT_SECRET` still contains the old example value `replace-with-at-least-32-random-characters`, run `python -m scripts.bootstrap_security`; it will replace that unsafe value with a random secret. Existing valid random secrets are preserved.
5. Run `alembic upgrade head` (expected head remains `b9f7d3c2a104`).
6. Regenerate/verify release artifacts only when making a release commit; normal runtime setup does not need to regenerate them.
7. Run the complete v0.9.1 verifier.

## Behavior changes

- Multipart analysis uploads can carry one bounded metadata object per file.
- The legacy single-file `connector_id` form field remains supported for compatibility.
- Streamlit sends connector overrides/options using `source_metadata` and reads upload limits from `/api/v1/system/security`.
- `.ndjson` is accepted at the upload security boundary.
- Known/example JWT values are invalid even when longer than 32 characters.

## Rollback

No schema downgrade is required to return to v0.9.0. Restore the v0.9.0 code/tag and retain the same database revision. If v0.9.1 generated a new JWT secret from an unsafe placeholder, do not intentionally restore the known placeholder value.
