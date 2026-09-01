# Upgrade from v0.4.1 to v0.5.0

v0.5.0 does not introduce a new Alembic revision. Existing v0.4.1 databases remain compatible because source manifests and aggregate parser statistics are stored in the existing JSON metadata fields.

Preserve these items during replacement:

- `.git`
- `.env`
- `database/threatlens.db`

Do not copy the old source tree over the new release. Install the new source, restore the three preserved items, run `setup.ps1`, then run `verify.ps1`.
