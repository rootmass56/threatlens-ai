from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = ROOT / "database" / "threatlens.db"
EXPECTED_REVISION: Final[str] = "d4a7c0e51010"

# Ordered to satisfy foreign keys while preserving source primary keys.
OPERATIONAL_TABLES: Final[tuple[str, ...]] = (
    "analysis_sessions",
    "events",
    "alerts",
    "incidents",
    "alert_events",
    "incident_alerts",
    "correlation_runs",
    "correlation_entities",
    "correlation_relationships",
    "incident_entities",
    "attack_graph_snapshots",
    "investigation_notes",
    "evidence",
    "rag_investigation_queries",
)

# Security identity and current ATT&CK catalogue state deliberately stay owned by v0.12.
PRESERVED_TARGET_TABLES: Final[tuple[str, ...]] = (
    "security_roles",
    "user_accounts",
    "user_roles",
    "refresh_tokens",
    "login_attempts",
    "attack_catalog_versions",
    "attack_objects",
    "attack_relationships",
    "rule_attack_mappings",
)

OPERATIONAL_AUDIT_ENTITY_TYPES: Final[tuple[str, ...]] = (
    "analysis_session",
    "incident",
    "rag_knowledge",
)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }


def _integrity(connection: sqlite3.Connection) -> str:
    return str(connection.execute("PRAGMA integrity_check").fetchone()[0])


def _revision(connection: sqlite3.Connection) -> str:
    tables = _tables(connection)
    if "alembic_version" not in tables:
        return ""
    row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    return str(row[0]) if row else ""


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')]


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _validate_schema(source: sqlite3.Connection, target: sqlite3.Connection) -> None:
    source_tables = _tables(source)
    target_tables = _tables(target)
    missing_source = [name for name in OPERATIONAL_TABLES if name not in source_tables]
    missing_target = [name for name in OPERATIONAL_TABLES if name not in target_tables]
    if missing_source:
        raise RuntimeError(
            "Source database is missing operational tables: " + ", ".join(missing_source)
        )
    if missing_target:
        raise RuntimeError(
            "Target database is missing operational tables: " + ", ".join(missing_target)
        )

    for table in OPERATIONAL_TABLES:
        source_columns = _columns(source, table)
        target_columns = _columns(target, table)
        if source_columns != target_columns:
            raise RuntimeError(
                f"Schema mismatch for {table}. Source columns={source_columns}; "
                f"target columns={target_columns}."
            )


def _delete_target_operational_data(target: sqlite3.Connection) -> None:
    # Delete in reverse dependency order. Audit entries are handled separately.
    for table in reversed(OPERATIONAL_TABLES):
        target.execute(f"DELETE FROM {_quote(table)}")
    placeholders = ",".join("?" for _ in OPERATIONAL_AUDIT_ENTITY_TYPES)
    target.execute(
        f"DELETE FROM audit_logs WHERE entity_type IN ({placeholders})",
        OPERATIONAL_AUDIT_ENTITY_TYPES,
    )


def _copy_table(source: sqlite3.Connection, target: sqlite3.Connection, table: str) -> int:
    columns = _columns(source, table)
    quoted = ",".join(_quote(column) for column in columns)
    placeholders = ",".join("?" for _ in columns)
    rows = source.execute(f"SELECT {quoted} FROM {_quote(table)}").fetchall()
    if rows:
        target.executemany(
            f"INSERT INTO {_quote(table)} ({quoted}) VALUES ({placeholders})",
            [tuple(row[column] for column in columns) for row in rows],
        )
    return len(rows)


def _copy_operational_audit(source: sqlite3.Connection, target: sqlite3.Connection) -> int:
    if "audit_logs" not in _tables(source) or "audit_logs" not in _tables(target):
        return 0
    columns = [
        column
        for column in _columns(source, "audit_logs")
        if column != "id" and column in _columns(target, "audit_logs")
    ]
    placeholders_for_types = ",".join("?" for _ in OPERATIONAL_AUDIT_ENTITY_TYPES)
    quoted = ",".join(_quote(column) for column in columns)
    rows = source.execute(
        f"SELECT {quoted} FROM audit_logs WHERE entity_type IN ({placeholders_for_types}) "
        "ORDER BY id",
        OPERATIONAL_AUDIT_ENTITY_TYPES,
    ).fetchall()
    if rows:
        target.executemany(
            f"INSERT INTO audit_logs ({quoted}) VALUES ({','.join('?' for _ in columns)})",
            [tuple(row[column] for column in columns) for row in rows],
        )
    return len(rows)


def migrate(
    *,
    source_path: Path,
    target_path: Path,
    replace_operational_data: bool,
    dry_run: bool,
) -> dict[str, object]:
    source_path = source_path.resolve()
    target_path = target_path.resolve()
    if source_path == target_path:
        raise RuntimeError("Source and target database paths must be different.")
    if not source_path.is_file():
        raise RuntimeError(f"Source database not found: {source_path}")
    if not target_path.is_file():
        raise RuntimeError(f"Target database not found: {target_path}")

    with _connect(source_path) as source, _connect(target_path) as target:
        source_integrity = _integrity(source)
        target_integrity = _integrity(target)
        if source_integrity.lower() != "ok" or target_integrity.lower() != "ok":
            raise RuntimeError(
                "SQLite integrity check failed: "
                f"source={source_integrity}; target={target_integrity}"
            )

        source_revision = _revision(source)
        target_revision = _revision(target)
        if source_revision != EXPECTED_REVISION or target_revision != EXPECTED_REVISION:
            raise RuntimeError(
                "Operational migration requires both databases at the v0.11.1/v0.12-compatible "
                f"Alembic head {EXPECTED_REVISION}; source={source_revision!r}, "
                f"target={target_revision!r}."
            )
        _validate_schema(source, target)

        source_counts = {table: _count(source, table) for table in OPERATIONAL_TABLES}
        target_counts_before = {table: _count(target, table) for table in OPERATIONAL_TABLES}
        target_nonempty = {table: count for table, count in target_counts_before.items() if count}
        if target_nonempty and not replace_operational_data:
            raise RuntimeError(
                "Target already contains operational SOC data. Re-run with "
                "--replace-operational-data only after reviewing the automatic backup. "
                f"Non-empty tables: {target_nonempty}"
            )

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = target_path.with_name(
            f"{target_path.stem}.pre-v0111-migration-{timestamp}{target_path.suffix}"
        )
        result: dict[str, object] = {
            "status": "dry_run" if dry_run else "migrated",
            "source": str(source_path),
            "target": str(target_path),
            "source_revision": source_revision,
            "target_revision": target_revision,
            "source_integrity": source_integrity,
            "target_integrity": target_integrity,
            "source_counts": source_counts,
            "target_counts_before": target_counts_before,
            "security_tables_preserved": list(PRESERVED_TARGET_TABLES),
            "audit_entity_types_migrated": list(OPERATIONAL_AUDIT_ENTITY_TYPES),
            "backup_path": None if dry_run else str(backup_path),
        }
        if dry_run:
            return result

        with sqlite3.connect(backup_path) as backup_connection:
            target.backup(backup_connection)

        copied: dict[str, int] = {}
        try:
            target.execute("BEGIN IMMEDIATE")
            if target_nonempty:
                _delete_target_operational_data(target)
            for table in OPERATIONAL_TABLES:
                copied[table] = _copy_table(source, target, table)
            copied["audit_logs"] = _copy_operational_audit(source, target)
            target.commit()
        except Exception:
            target.rollback()
            raise

        final_integrity = _integrity(target)
        if final_integrity.lower() != "ok":
            raise RuntimeError(
                "Post-migration integrity check failed. The pre-migration backup remains "
                f"available at {backup_path}. Result={final_integrity}"
            )
        target_counts_after = {table: _count(target, table) for table in OPERATIONAL_TABLES}

        result.update(
            {
                "copied": copied,
                "target_counts_after": target_counts_after,
                "post_migration_integrity": final_integrity,
            }
        )
        return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Safely migrate v0.11.1 operational SOC data into the v0.12 runtime database "
            "without importing old users, passwords, tokens or ATT&CK catalogue state."
        )
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="Path to the v0.11.1 SQLite database",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help="Path to the v0.12 SQLite database",
    )
    parser.add_argument(
        "--replace-operational-data",
        action="store_true",
        help=("Replace existing v0.12 operational SOC data after creating an automatic backup"),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate compatibility and show counts without writing",
    )
    args = parser.parse_args()
    result = migrate(
        source_path=args.source,
        target_path=args.target,
        replace_operational_data=args.replace_operational_data,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
