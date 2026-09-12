from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import text

from database.session import engine

QUERIES = {
    "largest_tables": """
        SELECT relname AS table_name,
               pg_total_relation_size(relid) AS total_bytes,
               n_live_tup AS estimated_rows,
               n_dead_tup AS dead_rows
        FROM pg_stat_user_tables
        ORDER BY pg_total_relation_size(relid) DESC
        LIMIT 20
    """,
    "index_usage": """
        SELECT relname AS table_name,
               seq_scan,
               idx_scan,
               CASE WHEN seq_scan + idx_scan = 0 THEN NULL
                    ELSE round((100.0 * idx_scan / (seq_scan + idx_scan))::numeric, 2)
               END AS index_scan_pct
        FROM pg_stat_user_tables
        ORDER BY seq_scan DESC, relname
        LIMIT 30
    """,
    "unused_indexes": """
        SELECT schemaname, relname AS table_name, indexrelname AS index_name,
               idx_scan, pg_relation_size(indexrelid) AS bytes
        FROM pg_stat_user_indexes
        WHERE idx_scan = 0
        ORDER BY pg_relation_size(indexrelid) DESC
        LIMIT 30
    """,
    "extensions": "SELECT extname, extversion FROM pg_extension ORDER BY extname",
}


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise SystemExit("Batch-7 database performance audit requires PostgreSQL.")
    report: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dialect": engine.dialect.name,
    }
    with engine.connect() as connection:
        for name, query in QUERIES.items():
            rows = connection.execute(text(query)).mappings().all()
            report[name] = [dict(row) for row in rows]
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
