# Batch 7 Backup / Restore / DR

Batch 7 uses PostgreSQL custom-format dumps with a SHA-256 manifest. The standard smoke restore always restores into a separate temporary database and deletes it afterward, proving the backup without altering the live `threatlens` database.

- `scripts/backup_batch7.ps1` — create a durable backup under `D:\ThreatLensAI_Runtime\backups\batch7`.
- `scripts/restore_batch7_smoke.ps1` — isolated restore verification.
- `scripts/restore_batch7.ps1` — guarded approved restore; primary database overwrite requires the explicit `-AllowPrimaryDatabaseRestore` switch.

Target operational objectives for the final project must be measured and documented rather than invented. Batch 7 runbooks provide initial RPO/RTO guidance, but the accepted values come from timed backup/restore UAT.
