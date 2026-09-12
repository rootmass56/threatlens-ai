
from __future__ import annotations

from sqlalchemy import inspect, text

from database.session import engine
from rag.config import RagSettings
from rag.vector_store import PgVectorStore


def main() -> int:
    if engine.dialect.name != "postgresql":
        raise SystemExit(f"Expected PostgreSQL; active dialect is {engine.dialect.name!r}.")
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        extension = connection.execute(
            text("SELECT extversion FROM pg_extension WHERE extname='vector'")
        ).scalar_one_or_none()
        if not extension:
            raise SystemExit("pgvector extension is not installed.")
    tables = set(inspect(engine).get_table_names())
    required = {
        "analysis_sessions",
        "events",
        "alerts",
        "incidents",
        "audit_logs",
        "rag_investigation_queries",
        "ai_investigation_jobs",
    }
    missing = sorted(required - tables)
    if missing:
        raise SystemExit(f"PostgreSQL schema is missing required tables: {missing}")

    settings = RagSettings.from_environment()
    if settings.vector_backend != "pgvector":
        raise SystemExit("THREATLENS_RAG_VECTOR_BACKEND is not pgvector.")
    store = PgVectorStore(
        database_url=settings.pgvector_database_url,
        collection_name=settings.collection_name,
        dimensions=settings.embedding_dimensions,
        hnsw_enabled=settings.pgvector_hnsw_enabled,
    )
    ready, detail = store.ready()
    if not ready:
        raise SystemExit(f"pgvector store is not ready: {detail}")

    print("BATCH 5 POSTGRESQL + PGVECTOR ACCEPTANCE: PASS")
    print(f"database dialect : {engine.dialect.name}")
    print(f"pgvector version : {extension}")
    print(f"vector backend   : {store.backend_name}")
    print(f"indexed chunks   : {store.count()}")
    if detail:
        print(f"vector detail    : {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
