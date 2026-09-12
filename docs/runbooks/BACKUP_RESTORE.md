# Runbook — Backup / Restore

## Backup

Run `scripts/backup_batch7.ps1`. Retain the dump and `manifest.json` together. Verify SHA-256 before transferring or restoring.

## Restore smoke

Run `scripts/restore_batch7_smoke.ps1 -BackupDirectory <path>`. The smoke flow restores into an isolated temporary database, verifies table population and pgvector, then deletes that temporary database.

## Approved restore

Use `scripts/restore_batch7.ps1`. Restoring over the primary `threatlens` database is blocked unless `-AllowPrimaryDatabaseRestore` is explicitly supplied during an approved recovery window. Stop API/worker writes before primary restore.

Measure actual backup duration, restore duration and acceptable data-loss window before declaring final RTO/RPO.
