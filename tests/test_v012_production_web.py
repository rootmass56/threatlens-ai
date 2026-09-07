
from __future__ import annotations

import json
from pathlib import Path

from api.config import SecuritySettings
from api.version import THREATLENS_VERSION
from database.session import normalize_database_url, psycopg_database_url
from rag.config import RagSettings
from rag.embeddings import OllamaEmbeddingProvider
from rag.llm import OllamaInvestigationGenerator
from rag.models import KnowledgeChunk
from rag.vector_store import PgVectorStore

ROOT = Path(__file__).resolve().parents[1]


def test_v012_version_is_current_release() -> None:
    assert THREATLENS_VERSION == "0.14.0"


def test_v012_render_postgres_url_normalizes_to_psycopg_driver() -> None:
    assert normalize_database_url("postgres://user:pass@db/threatlens") == (
        "postgresql+psycopg://user:pass@db/threatlens"
    )


def test_v012_postgresql_url_normalizes_to_psycopg_driver() -> None:
    assert normalize_database_url("postgresql://user:pass@db/threatlens") == (
        "postgresql+psycopg://user:pass@db/threatlens"
    )


def test_v012_sqlalchemy_postgres_url_converts_back_for_psycopg() -> None:
    assert psycopg_database_url("postgresql+psycopg://user:pass@db/threatlens") == (
        "postgresql://user:pass@db/threatlens"
    )


def test_v012_rag_accepts_pgvector_backend(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_RAG_VECTOR_BACKEND", "pgvector")
    loaded = RagSettings.from_environment()
    assert loaded.vector_backend == "pgvector"
    assert loaded.embedding_dimensions == 1024


def test_v012_default_compact_qwen35_profiles(monkeypatch) -> None:
    for name in (
        "THREATLENS_RAG_STANDARD_LLM_MODEL",
        "THREATLENS_RAG_LLM_MODEL",
        "THREATLENS_RAG_DEEP_LLM_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    loaded = RagSettings.from_environment()
    assert loaded.llm_model == "qwen3.5:4b"
    assert loaded.deep_llm_model == "qwen3.5:9b"
    assert loaded.embedding_batch_size == 4
    assert loaded.read_timeout_seconds == 120


def test_v012_qwen3_embedding_remains_1024d_default(monkeypatch) -> None:
    monkeypatch.delenv("THREATLENS_RAG_EMBEDDING_MODEL", raising=False)
    monkeypatch.delenv("THREATLENS_RAG_EMBEDDING_DIMENSIONS", raising=False)
    loaded = RagSettings.from_environment()
    assert loaded.embedding_model == "qwen3-embedding:0.6b"
    assert loaded.embedding_dimensions == 1024


def test_v012_llm_remote_api_key_uses_bearer_auth() -> None:
    generator = OllamaInvestigationGenerator(
        base_url="https://inference.example",
        model_name="qwen3.5:4b",
        connect_timeout=3,
        read_timeout=30,
        api_key="secret-token",
    )
    assert generator.headers["Authorization"] == "Bearer secret-token"
    assert generator.headers["User-Agent"] == "ThreatLens-RAG/0.12.0"


def test_v012_embedding_remote_api_key_uses_bearer_auth() -> None:
    provider = OllamaEmbeddingProvider(
        base_url="https://inference.example",
        model_name="qwen3-embedding:0.6b",
        connect_timeout=3,
        read_timeout=30,
        api_key="secret-token",
    )
    assert provider.headers["Authorization"] == "Bearer secret-token"
    assert provider.headers["User-Agent"] == "ThreatLens-RAG/0.12.0"


def test_v012_pgvector_literal_is_deterministic() -> None:
    assert PgVectorStore._vector_literal([1.0, -0.5, 0.125]) == "[1,-0.5,0.125]"


def test_v012_pgvector_reconstructs_every_knowledge_chunk_field() -> None:
    row = (
        "a" * 32,
        "source-1",
        "Title",
        "attack",
        "19.1",
        "tier-1",
        "Technique",
        "Document text",
        "ref://source",
        "b" * 64,
        {"technique_id": "T1059.001"},
    )
    chunk = PgVectorStore._chunk_from_row(row)
    assert chunk == KnowledgeChunk(
        chunk_id="a" * 32,
        source_id="source-1",
        title="Title",
        source_kind="attack",
        version="19.1",
        trust_tier="tier-1",
        section="Technique",
        text="Document text",
        source_reference="ref://source",
        content_sha256="b" * 64,
        metadata={"technique_id": "T1059.001"},
    )


def test_v012_pgvector_schema_version_is_release_scoped() -> None:
    assert PgVectorStore._SCHEMA_VERSION == "0.12.0"


def test_v012_alembic_batch_mode_is_sqlite_only() -> None:
    source = (ROOT / "migrations" / "env.py").read_text(encoding="utf-8")
    assert 'render_as_batch=connection.dialect.name == "sqlite"' in source


def test_v012_render_blueprint_uses_postgres_pgvector_and_staged_startup() -> None:
    source = (ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "plan: free" in source
    startup = (ROOT / "scripts" / "start_production.sh").read_text(encoding="utf-8")
    assert "python -m alembic upgrade head" in startup
    assert "python -m scripts.bootstrap_security" in startup
    assert "THREATLENS_RAG_VECTOR_BACKEND" in source
    assert "value: pgvector" in source
    assert "fromDatabase:" in source


def test_v012_docker_runs_fastapi_as_non_root() -> None:
    source = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER threatlens" in source
    assert "scripts/start_production.sh" in source
    assert "/api/v1/health/live" in source


def test_v012_frontend_package_is_react_vite_typescript() -> None:
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert package["dependencies"]["react"] == "19.2.8"
    assert package["devDependencies"]["vite"] == "8.2.2"
    assert package["devDependencies"]["typescript"] == "7.0.2"


def test_v012_frontend_exposes_only_api_url_as_public_configuration() -> None:
    env = (ROOT / "frontend" / ".env.example").read_text(encoding="utf-8")
    api_source = (ROOT / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    assert env.strip().startswith("VITE_THREATLENS_API_URL=")
    assert "JWT" not in env and "API_KEY" not in env
    assert "/api/v1/auth/refresh" in api_source
    assert "threatlens:session-expired" in api_source


def test_v012_vercel_has_spa_rewrite_and_security_headers() -> None:
    config = json.loads((ROOT / "frontend" / "vercel.json").read_text(encoding="utf-8"))
    assert config["rewrites"][0]["destination"] == "/index.html"
    names = {item["key"] for item in config["headers"][0]["headers"]}
    assert {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
    } <= names


def test_v012_local_cors_defaults_target_vite(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_JWT_SECRET", "x" * 48)
    monkeypatch.delenv("THREATLENS_ALLOWED_ORIGINS", raising=False)
    settings = SecuritySettings.from_environment()
    assert "http://localhost:5173" in settings.allowed_origins


def test_v012_frontend_gate_requires_typecheck_build_and_audit() -> None:
    source = (ROOT / "scripts" / "verify_frontend.ps1").read_text(encoding="utf-8")
    assert "npm run typecheck" in source
    assert "npm run build" in source
    assert "npm audit --audit-level=high" in source
