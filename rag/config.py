
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from database.session import DATABASE_URL

ROOT_DIR = Path(__file__).resolve().parents[1]


def _as_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(name: str, default: int, minimum: int = 1) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}.")
    return parsed


def _as_float(name: str, default: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return parsed


@dataclass(frozen=True)
class RagSettings:
    enabled: bool
    ollama_base_url: str
    llm_model: str
    embedding_model: str
    vector_backend: str
    embedding_backend: str
    vector_path: Path
    collection_name: str
    top_k: int
    embedding_batch_size: int
    minimum_relevance: float
    max_incident_context_chars: int
    max_knowledge_context_chars: int
    max_question_chars: int
    connect_timeout_seconds: int
    read_timeout_seconds: int
    ollama_num_ctx: int
    ollama_num_predict: int
    exact_knowledge_limit: int
    include_analyst_notes: bool
    deep_llm_model: str = "qwen3.5:9b"
    deep_read_timeout_seconds: int = 600
    deep_ollama_num_ctx: int = 8192
    deep_ollama_num_predict: int = 1400
    auto_deep_threshold: int = 5
    fallback_to_standard: bool = True
    standard_fallback_max_primary_seconds: int = 30
    ollama_api_key: str | None = None
    pgvector_database_url: str = DATABASE_URL
    embedding_dimensions: int = 1024
    pgvector_hnsw_enabled: bool = True

    @classmethod
    def from_environment(cls) -> RagSettings:
        vector_backend = os.getenv("THREATLENS_RAG_VECTOR_BACKEND", "sqlite").strip().lower()
        embedding_backend = os.getenv("THREATLENS_RAG_EMBEDDING_BACKEND", "ollama").strip().lower()
        if vector_backend not in {"sqlite", "memory", "pgvector"}:
            raise ValueError(
                "THREATLENS_RAG_VECTOR_BACKEND must be 'sqlite', 'memory', or 'pgvector'."
            )
        if embedding_backend not in {"ollama", "hashing"}:
            raise ValueError("THREATLENS_RAG_EMBEDDING_BACKEND must be 'ollama' or 'hashing'.")

        raw_path = os.getenv("THREATLENS_RAG_VECTOR_PATH")
        if raw_path is None:
            legacy = os.getenv("THREATLENS_RAG_CHROMA_PATH", "").strip()
            raw_path = (
                legacy
                if legacy and not legacy.replace("\\", "/").endswith("data/rag/chroma_db")
                else "data/rag/vector_store.sqlite3"
            )
        vector_path = Path(raw_path.strip())
        if not vector_path.is_absolute():
            vector_path = ROOT_DIR / vector_path

        standard_model = os.getenv(
            "THREATLENS_RAG_STANDARD_LLM_MODEL",
            os.getenv("THREATLENS_RAG_LLM_MODEL", "qwen3.5:4b"),
        ).strip()
        api_key = os.getenv("THREATLENS_OLLAMA_API_KEY", "").strip() or None
        return cls(
            enabled=_as_bool("THREATLENS_RAG_ENABLED", True),
            ollama_base_url=os.getenv("THREATLENS_OLLAMA_URL", "http://127.0.0.1:11434").rstrip(
                "/"
            ),
            llm_model=standard_model,
            embedding_model=os.getenv(
                "THREATLENS_RAG_EMBEDDING_MODEL", "qwen3-embedding:0.6b"
            ).strip(),
            vector_backend=vector_backend,
            embedding_backend=embedding_backend,
            vector_path=vector_path,
            collection_name=os.getenv(
                "THREATLENS_RAG_COLLECTION", "threatlens-v0120-knowledge"
            ).strip(),
            top_k=_as_int("THREATLENS_RAG_TOP_K", 3),
            embedding_batch_size=_as_int("THREATLENS_RAG_EMBED_BATCH_SIZE", 4),
            minimum_relevance=_as_float("THREATLENS_RAG_MIN_RELEVANCE", 0.18),
            max_incident_context_chars=_as_int("THREATLENS_RAG_MAX_INCIDENT_CONTEXT_CHARS", 6500),
            max_knowledge_context_chars=_as_int("THREATLENS_RAG_MAX_KNOWLEDGE_CONTEXT_CHARS", 6000),
            max_question_chars=_as_int("THREATLENS_RAG_MAX_QUESTION_CHARS", 2000),
            connect_timeout_seconds=_as_int("THREATLENS_RAG_CONNECT_TIMEOUT_SECONDS", 3),
            read_timeout_seconds=_as_int("THREATLENS_RAG_READ_TIMEOUT_SECONDS", 120),
            ollama_num_ctx=_as_int("THREATLENS_RAG_OLLAMA_NUM_CTX", 8192, minimum=2048),
            ollama_num_predict=_as_int("THREATLENS_RAG_OLLAMA_NUM_PREDICT", 900, minimum=128),
            exact_knowledge_limit=_as_int("THREATLENS_RAG_EXACT_KNOWLEDGE_LIMIT", 8),
            include_analyst_notes=_as_bool("THREATLENS_RAG_INCLUDE_ANALYST_NOTES", True),
            deep_llm_model=os.getenv("THREATLENS_RAG_DEEP_LLM_MODEL", "qwen3.5:9b").strip(),
            deep_read_timeout_seconds=_as_int("THREATLENS_RAG_DEEP_READ_TIMEOUT_SECONDS", 600),
            deep_ollama_num_ctx=_as_int("THREATLENS_RAG_DEEP_OLLAMA_NUM_CTX", 16384, minimum=4096),
            deep_ollama_num_predict=_as_int(
                "THREATLENS_RAG_DEEP_OLLAMA_NUM_PREDICT", 1600, minimum=512
            ),
            auto_deep_threshold=_as_int("THREATLENS_RAG_AUTO_DEEP_THRESHOLD", 5),
            fallback_to_standard=_as_bool("THREATLENS_RAG_FALLBACK_TO_STANDARD", True),
            standard_fallback_max_primary_seconds=_as_int(
                "THREATLENS_RAG_STANDARD_FALLBACK_MAX_PRIMARY_SECONDS", 30
            ),
            ollama_api_key=api_key,
            pgvector_database_url=os.getenv(
                "THREATLENS_RAG_PGVECTOR_DATABASE_URL", DATABASE_URL
            ).strip(),
            embedding_dimensions=_as_int("THREATLENS_RAG_EMBEDDING_DIMENSIONS", 1024, minimum=32),
            pgvector_hnsw_enabled=_as_bool("THREATLENS_RAG_PGVECTOR_HNSW", True),
        )


@lru_cache(maxsize=1)
def get_rag_settings() -> RagSettings:
    return RagSettings.from_environment()
