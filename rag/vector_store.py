
from __future__ import annotations

import json
import math
import sqlite3
import struct
import threading
from pathlib import Path
from typing import Protocol

from rag.models import KnowledgeChunk, RetrievedChunk


class VectorStore(Protocol):
    backend_name: str

    def upsert(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
    ) -> None: ...

    def delete_source_ids(self, source_ids: list[str]) -> int: ...

    def clear(self) -> int: ...

    def query(
        self,
        embedding: list[float],
        *,
        top_k: int,
    ) -> list[RetrievedChunk]: ...

    def get_source_ids(self, source_ids: list[str]) -> list[RetrievedChunk]: ...

    def count(self) -> int: ...

    def ready(self) -> tuple[bool, str | None]: ...

    def read_manifest(self) -> dict | None: ...

    def write_manifest(self, payload: dict) -> None: ...


def _dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right, strict=False))


def _cosine(left: list[float], right: list[float], right_norm: float | None = None) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    if left_norm <= 0.0:
        return 0.0
    stored_norm = right_norm
    if stored_norm is None or stored_norm <= 0.0:
        stored_norm = math.sqrt(sum(value * value for value in right))
    if stored_norm <= 0.0:
        return 0.0
    return _dot(left, right) / (left_norm * stored_norm)


class MemoryVectorStore:
    backend_name = "memory"

    def __init__(self) -> None:
        self._records: dict[str, tuple[KnowledgeChunk, list[float]]] = {}
        self._manifest: dict | None = None

    def upsert(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
    ) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError("Chunk and embedding counts must match.")
        for chunk, embedding in zip(chunks, embeddings, strict=True):
            self._records[chunk.chunk_id] = (chunk, list(embedding))

    def delete_source_ids(self, source_ids: list[str]) -> int:
        wanted = set(source_ids)
        doomed = [key for key, (chunk, _) in self._records.items() if chunk.source_id in wanted]
        for key in doomed:
            self._records.pop(key, None)
        return len(doomed)

    def clear(self) -> int:
        deleted = len(self._records)
        self._records.clear()
        return deleted

    def query(self, embedding: list[float], *, top_k: int) -> list[RetrievedChunk]:
        scored = [(_cosine(embedding, vector), chunk) for chunk, vector in self._records.values()]
        scored.sort(key=lambda item: (-item[0], item[1].chunk_id))
        output: list[RetrievedChunk] = []
        for index, (score, chunk) in enumerate(scored[:top_k], start=1):
            relevance = max(0.0, min(1.0, (score + 1.0) / 2.0))
            output.append(
                RetrievedChunk(
                    chunk=chunk,
                    relevance=relevance,
                    rank=index,
                )
            )
        return output

    def get_source_ids(self, source_ids: list[str]) -> list[RetrievedChunk]:
        wanted = list(dict.fromkeys(source_ids))
        output: list[RetrievedChunk] = []
        for source_id in wanted:
            chunks = sorted(
                (chunk for chunk, _ in self._records.values() if chunk.source_id == source_id),
                key=lambda item: item.chunk_id,
            )
            for chunk in chunks:
                output.append(
                    RetrievedChunk(
                        chunk=chunk,
                        relevance=1.0,
                        rank=len(output) + 1,
                    )
                )
        return output

    def count(self) -> int:
        return len(self._records)

    def ready(self) -> tuple[bool, str | None]:
        return True, None

    def read_manifest(self) -> dict | None:
        if self._manifest is None:
            return None
        return json.loads(json.dumps(self._manifest))

    def write_manifest(self, payload: dict) -> None:
        self._manifest = json.loads(json.dumps(payload))


class SQLiteVectorStore:
    """ThreatLens-owned persistent vector store backed only by Python's sqlite3.

    The RAG corpus is intentionally small (roughly one thousand governed chunks in the
    v0.11 baseline), so an exact cosine scan is simple, deterministic and avoids exposing
    a separate vector-database server or carrying an unnecessary network-capable dependency.
    """

    backend_name = "sqlite"
    _SCHEMA_VERSION = "1"

    def __init__(self, *, path: Path, collection_name: str) -> None:
        self.path = path
        self.collection_name = collection_name
        self._lock = threading.RLock()
        self._error: str | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                self._initialize(connection)
        except Exception as error:  # pragma: no cover - filesystem/runtime dependent
            self._error = str(error)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vector_store_meta (
                collection_name TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                manifest_json TEXT
            )
            """
        )
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(vector_store_meta)").fetchall()
        }
        if "manifest_json" not in columns:
            connection.execute("ALTER TABLE vector_store_meta ADD COLUMN manifest_json TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vector_chunks (
                collection_name TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                title TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                version TEXT NOT NULL,
                trust_tier TEXT NOT NULL,
                section TEXT NOT NULL,
                document TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                dimensions INTEGER NOT NULL,
                embedding_norm REAL NOT NULL,
                embedding BLOB NOT NULL,
                PRIMARY KEY (collection_name, chunk_id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vector_chunks_collection_source
            ON vector_chunks (collection_name, source_id)
            """
        )
        connection.execute(
            """
            INSERT INTO vector_store_meta (collection_name, schema_version)
            VALUES (?, ?)
            ON CONFLICT(collection_name) DO UPDATE SET schema_version=excluded.schema_version
            """,
            (self.collection_name, self._SCHEMA_VERSION),
        )
        connection.commit()

    def _require(self) -> None:
        if self._error is not None:
            raise RuntimeError(
                f"ThreatLens SQLite vector storage is unavailable. Details: {self._error}"
            )

    @staticmethod
    def _pack_embedding(embedding: list[float]) -> bytes:
        if not embedding:
            raise ValueError("Embeddings must contain at least one dimension.")
        return struct.pack(f"<{len(embedding)}f", *embedding)

    @staticmethod
    def _unpack_embedding(payload: bytes, dimensions: int) -> list[float]:
        expected = dimensions * 4
        if len(payload) != expected:
            raise RuntimeError("Stored vector payload length does not match its dimensions.")
        return list(struct.unpack(f"<{dimensions}f", payload))

    @staticmethod
    def _chunk(row: sqlite3.Row) -> KnowledgeChunk:
        try:
            metadata = json.loads(str(row["metadata_json"]))
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        return KnowledgeChunk(
            chunk_id=str(row["chunk_id"]),
            source_id=str(row["source_id"]),
            title=str(row["title"]),
            source_kind=str(row["source_kind"]),
            version=str(row["version"]),
            trust_tier=str(row["trust_tier"]),
            section=str(row["section"]),
            text=str(row["document"]),
            source_reference=str(row["source_reference"]),
            content_sha256=str(row["content_sha256"]),
            metadata=metadata if isinstance(metadata, dict) else {},
        )

    def upsert(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
    ) -> None:
        if not chunks:
            return
        if len(chunks) != len(embeddings):
            raise ValueError("Chunk and embedding counts must match.")
        rows = []
        for chunk, embedding in zip(chunks, embeddings, strict=True):
            norm = math.sqrt(sum(value * value for value in embedding))
            rows.append(
                (
                    self.collection_name,
                    chunk.chunk_id,
                    chunk.source_id,
                    chunk.title,
                    chunk.source_kind,
                    chunk.version,
                    chunk.trust_tier,
                    chunk.section,
                    chunk.text,
                    chunk.source_reference,
                    chunk.content_sha256,
                    json.dumps(chunk.metadata, sort_keys=True, default=str),
                    len(embedding),
                    norm,
                    self._pack_embedding(embedding),
                )
            )
        with self._lock:
            self._require()
            with self._connect() as connection:
                connection.executemany(
                    """
                    INSERT INTO vector_chunks (
                        collection_name, chunk_id, source_id, title, source_kind,
                        version, trust_tier, section, document, source_reference,
                        content_sha256, metadata_json, dimensions, embedding_norm, embedding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(collection_name, chunk_id) DO UPDATE SET
                        source_id=excluded.source_id,
                        title=excluded.title,
                        source_kind=excluded.source_kind,
                        version=excluded.version,
                        trust_tier=excluded.trust_tier,
                        section=excluded.section,
                        document=excluded.document,
                        source_reference=excluded.source_reference,
                        content_sha256=excluded.content_sha256,
                        metadata_json=excluded.metadata_json,
                        dimensions=excluded.dimensions,
                        embedding_norm=excluded.embedding_norm,
                        embedding=excluded.embedding
                    """,
                    rows,
                )
                connection.commit()

    def delete_source_ids(self, source_ids: list[str]) -> int:
        wanted = list(dict.fromkeys(source_ids))
        if not wanted:
            return 0
        placeholders = ",".join("?" for _ in wanted)
        with self._lock:
            self._require()
            with self._connect() as connection:
                cursor = connection.execute(
                    f"DELETE FROM vector_chunks WHERE collection_name=? "
                    f"AND source_id IN ({placeholders})",
                    [self.collection_name, *wanted],
                )
                connection.commit()
                return max(int(cursor.rowcount), 0)

    def clear(self) -> int:
        with self._lock:
            self._require()
            with self._connect() as connection:
                cursor = connection.execute(
                    "DELETE FROM vector_chunks WHERE collection_name=?",
                    (self.collection_name,),
                )
                connection.commit()
                return max(int(cursor.rowcount), 0)

    def query(self, embedding: list[float], *, top_k: int) -> list[RetrievedChunk]:
        if not embedding or top_k <= 0:
            return []
        with self._lock:
            self._require()
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT chunk_id, source_id, title, source_kind, version, trust_tier,
                           section, document, source_reference, content_sha256,
                           metadata_json, dimensions, embedding_norm, embedding
                    FROM vector_chunks
                    WHERE collection_name=?
                    """,
                    (self.collection_name,),
                ).fetchall()

        scored: list[tuple[float, KnowledgeChunk]] = []
        for row in rows:
            dimensions = int(row["dimensions"])
            if dimensions != len(embedding):
                continue
            stored = self._unpack_embedding(bytes(row["embedding"]), dimensions)
            score = _cosine(embedding, stored, float(row["embedding_norm"]))
            scored.append((score, self._chunk(row)))
        scored.sort(key=lambda item: (-item[0], item[1].chunk_id))

        output: list[RetrievedChunk] = []
        for rank, (score, chunk) in enumerate(scored[:top_k], start=1):
            relevance = max(0.0, min(1.0, (score + 1.0) / 2.0))
            output.append(RetrievedChunk(chunk=chunk, relevance=relevance, rank=rank))
        return output

    def get_source_ids(self, source_ids: list[str]) -> list[RetrievedChunk]:
        wanted = list(dict.fromkeys(source_ids))
        if not wanted:
            return []
        placeholders = ",".join("?" for _ in wanted)
        with self._lock:
            self._require()
            with self._connect() as connection:
                rows = connection.execute(
                    f"""
                    SELECT chunk_id, source_id, title, source_kind, version, trust_tier,
                           section, document, source_reference, content_sha256, metadata_json
                    FROM vector_chunks
                    WHERE collection_name=? AND source_id IN ({placeholders})
                    ORDER BY source_id, chunk_id
                    """,
                    [self.collection_name, *wanted],
                ).fetchall()

        by_source: dict[str, list[KnowledgeChunk]] = {source_id: [] for source_id in wanted}
        for row in rows:
            by_source.setdefault(str(row["source_id"]), []).append(self._chunk(row))
        output: list[RetrievedChunk] = []
        for source_id in wanted:
            for chunk in by_source.get(source_id, []):
                output.append(RetrievedChunk(chunk=chunk, relevance=1.0, rank=len(output) + 1))
        return output

    def count(self) -> int:
        with self._lock:
            self._require()
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM vector_chunks WHERE collection_name=?",
                    (self.collection_name,),
                ).fetchone()
                return int(row["count"] if row is not None else 0)

    def ready(self) -> tuple[bool, str | None]:
        if self._error is not None:
            return False, self._error
        try:
            with self._lock, self._connect() as connection:
                self._initialize(connection)
            return True, None
        except Exception as error:  # pragma: no cover - filesystem/runtime dependent
            self._error = str(error)
            return False, self._error

    def read_manifest(self) -> dict | None:
        with self._lock:
            self._require()
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT manifest_json FROM vector_store_meta WHERE collection_name=?",
                    (self.collection_name,),
                ).fetchone()
        if row is None or not row["manifest_json"]:
            return None
        try:
            payload = json.loads(str(row["manifest_json"]))
        except (TypeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def write_manifest(self, payload: dict) -> None:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        with self._lock:
            self._require()
            with self._connect() as connection:
                connection.execute(
                    "UPDATE vector_store_meta SET manifest_json=? WHERE collection_name=?",
                    (serialized, self.collection_name),
                )
                connection.commit()


class PgVectorStore:
    """Production PostgreSQL vector store using the pgvector extension.

    The schema preserves every KnowledgeChunk field used by the governed RAG pipeline.
    HNSW creation is deliberately best-effort: failure to create the ANN index must never
    roll back the durable vector table or its data. Exact pgvector ordering remains valid.
    """

    backend_name = "pgvector"
    _SCHEMA_VERSION = "0.12.0"

    def __init__(
        self,
        *,
        database_url: str,
        collection_name: str,
        dimensions: int = 1024,
        hnsw_enabled: bool = True,
    ) -> None:
        self.database_url = database_url
        self.collection_name = collection_name
        self.dimensions = int(dimensions)
        self.hnsw_enabled = bool(hnsw_enabled)
        self._error: str | None = None
        self._hnsw_error: str | None = None
        try:
            with self._connect() as connection:
                self._initialize(connection)
            if self.hnsw_enabled:
                self._initialize_hnsw_best_effort()
        except Exception as error:  # pragma: no cover - depends on external PostgreSQL
            self._error = str(error)

    def _connect(self):
        try:
            import psycopg
        except ImportError as error:  # pragma: no cover - dependency gate covers production
            raise RuntimeError(
                "psycopg is required for the pgvector backend. Install the v0.12 dependencies."
            ) from error

        from database.session import psycopg_database_url

        return psycopg.connect(psycopg_database_url(self.database_url), autocommit=False)

    @staticmethod
    def _vector_literal(embedding: list[float]) -> str:
        if not embedding:
            raise ValueError("Embeddings must contain at least one dimension.")
        return "[" + ",".join(format(float(value), ".9g") for value in embedding) + "]"

    def _initialize(self, connection) -> None:
        with connection.cursor() as cursor:
            cursor.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS threatlens_vector_store_meta (
                    collection_name TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    dimensions INTEGER NOT NULL,
                    manifest_json JSONB,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cursor.execute(
                """
                ALTER TABLE threatlens_vector_store_meta
                ADD COLUMN IF NOT EXISTS manifest_json JSONB
                """
            )
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS threatlens_vector_chunks (
                    collection_name TEXT NOT NULL,
                    chunk_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    version TEXT NOT NULL,
                    trust_tier TEXT NOT NULL,
                    section TEXT NOT NULL,
                    document TEXT NOT NULL,
                    source_reference TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    metadata_json JSONB NOT NULL DEFAULT '{{}}'::jsonb,
                    embedding vector({self.dimensions}) NOT NULL,
                    PRIMARY KEY (collection_name, chunk_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_threatlens_vector_collection_source
                ON threatlens_vector_chunks (collection_name, source_id)
                """
            )
            cursor.execute(
                """
                INSERT INTO threatlens_vector_store_meta
                    (collection_name, schema_version, dimensions)
                VALUES (%s, %s, %s)
                ON CONFLICT (collection_name) DO UPDATE SET
                    schema_version=EXCLUDED.schema_version,
                    dimensions=EXCLUDED.dimensions,
                    updated_at=NOW()
                """,
                (self.collection_name, self._SCHEMA_VERSION, self.dimensions),
            )
        connection.commit()

    def _initialize_hnsw_best_effort(self) -> None:
        # Create the optional ANN index in a distinct transaction. If the managed database
        # plan/version does not support HNSW, the core vector table remains intact.
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_threatlens_vector_hnsw
                    ON threatlens_vector_chunks
                    USING hnsw (embedding vector_cosine_ops)
                    """
                )
                connection.commit()
        except Exception as error:  # pragma: no cover - PostgreSQL/extension dependent
            self._hnsw_error = str(error)

    def _require(self) -> None:
        if self._error is not None:
            raise RuntimeError(
                f"ThreatLens pgvector storage is unavailable. Details: {self._error}"
            )

    @staticmethod
    def _chunk_from_row(row: tuple) -> KnowledgeChunk:
        metadata = row[10]
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}
        return KnowledgeChunk(
            chunk_id=str(row[0]),
            source_id=str(row[1]),
            title=str(row[2]),
            source_kind=str(row[3]),
            version=str(row[4]),
            trust_tier=str(row[5]),
            section=str(row[6]),
            text=str(row[7]),
            source_reference=str(row[8]),
            content_sha256=str(row[9]),
            metadata=metadata if isinstance(metadata, dict) else {},
        )

    def upsert(self, chunks: list[KnowledgeChunk], embeddings: list[list[float]]) -> None:
        if not chunks:
            return
        if len(chunks) != len(embeddings):
            raise ValueError("Chunk and embedding counts must match.")
        for embedding in embeddings:
            if len(embedding) != self.dimensions:
                raise ValueError(
                    f"Embedding dimensions must equal {self.dimensions}; got {len(embedding)}."
                )

        rows = [
            (
                self.collection_name,
                chunk.chunk_id,
                chunk.source_id,
                chunk.title,
                chunk.source_kind,
                chunk.version,
                chunk.trust_tier,
                chunk.section,
                chunk.text,
                chunk.source_reference,
                chunk.content_sha256,
                json.dumps(chunk.metadata, sort_keys=True, default=str),
                self._vector_literal(embedding),
            )
            for chunk, embedding in zip(chunks, embeddings, strict=True)
        ]
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO threatlens_vector_chunks (
                    collection_name, chunk_id, source_id, title, source_kind, version,
                    trust_tier, section, document, source_reference, content_sha256,
                    metadata_json, embedding
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::vector)
                ON CONFLICT (collection_name, chunk_id) DO UPDATE SET
                    source_id=EXCLUDED.source_id,
                    title=EXCLUDED.title,
                    source_kind=EXCLUDED.source_kind,
                    version=EXCLUDED.version,
                    trust_tier=EXCLUDED.trust_tier,
                    section=EXCLUDED.section,
                    document=EXCLUDED.document,
                    source_reference=EXCLUDED.source_reference,
                    content_sha256=EXCLUDED.content_sha256,
                    metadata_json=EXCLUDED.metadata_json,
                    embedding=EXCLUDED.embedding
                """,
                rows,
            )
            connection.commit()

    def delete_source_ids(self, source_ids: list[str]) -> int:
        wanted = list(dict.fromkeys(source_ids))
        if not wanted:
            return 0
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM threatlens_vector_chunks "
                "WHERE collection_name=%s AND source_id = ANY(%s)",
                (self.collection_name, wanted),
            )
            deleted = max(int(cursor.rowcount), 0)
            connection.commit()
            return deleted

    def clear(self) -> int:
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM threatlens_vector_chunks WHERE collection_name=%s",
                (self.collection_name,),
            )
            deleted = max(int(cursor.rowcount), 0)
            connection.commit()
            return deleted

    def query(self, embedding: list[float], *, top_k: int) -> list[RetrievedChunk]:
        if not embedding or top_k <= 0:
            return []
        if len(embedding) != self.dimensions:
            return []
        self._require()
        literal = self._vector_literal(embedding)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT chunk_id, source_id, title, source_kind, version, trust_tier,
                       section, document, source_reference, content_sha256, metadata_json,
                       (1 - (embedding <=> %s::vector)) AS cosine_similarity
                FROM threatlens_vector_chunks
                WHERE collection_name=%s
                ORDER BY embedding <=> %s::vector, chunk_id
                LIMIT %s
                """,
                (literal, self.collection_name, literal, int(top_k)),
            )
            rows = cursor.fetchall()

        output: list[RetrievedChunk] = []
        for rank, row in enumerate(rows, start=1):
            score = float(row[11])
            # Match the v0.11 SQLite/Memory public relevance scale.
            relevance = max(0.0, min(1.0, (score + 1.0) / 2.0))
            output.append(
                RetrievedChunk(
                    chunk=self._chunk_from_row(row),
                    relevance=relevance,
                    rank=rank,
                )
            )
        return output

    def get_source_ids(self, source_ids: list[str]) -> list[RetrievedChunk]:
        wanted = list(dict.fromkeys(source_ids))
        if not wanted:
            return []
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT chunk_id, source_id, title, source_kind, version, trust_tier,
                       section, document, source_reference, content_sha256, metadata_json
                FROM threatlens_vector_chunks
                WHERE collection_name=%s AND source_id = ANY(%s)
                ORDER BY source_id, chunk_id
                """,
                (self.collection_name, wanted),
            )
            rows = cursor.fetchall()

        by_source: dict[str, list[KnowledgeChunk]] = {source_id: [] for source_id in wanted}
        for row in rows:
            by_source.setdefault(str(row[1]), []).append(self._chunk_from_row(row))
        output: list[RetrievedChunk] = []
        for source_id in wanted:
            for chunk in by_source.get(source_id, []):
                output.append(RetrievedChunk(chunk=chunk, relevance=1.0, rank=len(output) + 1))
        return output

    def count(self) -> int:
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM threatlens_vector_chunks WHERE collection_name=%s",
                (self.collection_name,),
            )
            row = cursor.fetchone()
            return int(row[0] if row else 0)

    def ready(self) -> tuple[bool, str | None]:
        if self._error is not None:
            return False, self._error
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            detail = None
            if self._hnsw_error:
                detail = "pgvector is ready; optional HNSW index is unavailable."
            return True, detail
        except Exception as error:  # pragma: no cover - external PostgreSQL dependent
            self._error = str(error)
            return False, self._error

    def read_manifest(self) -> dict | None:
        self._require()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT manifest_json FROM threatlens_vector_store_meta "
                "WHERE collection_name=%s",
                (self.collection_name,),
            )
            row = cursor.fetchone()
        if row is None or row[0] is None:
            return None
        payload = row[0]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None
        return payload if isinstance(payload, dict) else None

    def write_manifest(self, payload: dict) -> None:
        self._require()
        serialized = json.dumps(payload, sort_keys=True, default=str)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE threatlens_vector_store_meta "
                "SET manifest_json=%s::jsonb, updated_at=NOW() "
                "WHERE collection_name=%s",
                (serialized, self.collection_name),
            )
            connection.commit()
