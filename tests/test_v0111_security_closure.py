
from __future__ import annotations

import json
from pathlib import Path

from api.version import THREATLENS_VERSION
from rag.config import RagSettings
from rag.embeddings import HashingEmbeddingProvider
from rag.models import KnowledgeChunk
from rag.vector_store import SQLiteVectorStore
from scripts.verify_dependency_security import _load, verify_source_contract


def test_v0111_version_is_security_closure_release() -> None:
    assert THREATLENS_VERSION == "0.14.0"
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.14.0"' in pyproject


def test_v0111_reviewed_dependency_baseline_passes_source_contract() -> None:
    verify_source_contract(_load())


def test_v0111_chromadb_runtime_dependency_is_removed() -> None:
    for name in ("pyproject.toml", "requirements.txt", "constraints-windows-py311.txt"):
        source = Path(name).read_text(encoding="utf-8").casefold()
        assert "chromadb==" not in source
    vector_source = Path("rag/vector_store.py").read_text(encoding="utf-8")
    assert "import chromadb" not in vector_source
    assert "ChromaVectorStore" not in vector_source


def test_v0111_patched_dependency_versions_are_pinned() -> None:
    runtime = Path("requirements.txt").read_text(encoding="utf-8")
    dev = Path("requirements-dev.txt").read_text(encoding="utf-8")
    assert "python-multipart==0.0.32" in runtime
    assert "requests==2.34.2" in runtime
    assert "pytest==9.1.1" in dev


def test_v0111_default_vector_backend_is_builtin_sqlite(monkeypatch) -> None:
    for key in (
        "THREATLENS_RAG_VECTOR_BACKEND",
        "THREATLENS_RAG_VECTOR_PATH",
        "THREATLENS_RAG_CHROMA_PATH",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = RagSettings.from_environment()
    assert settings.vector_backend == "sqlite"
    assert settings.vector_path.as_posix().endswith("data/rag/vector_store.sqlite3")


def test_v0111_legacy_chroma_default_path_migrates_to_sqlite(monkeypatch) -> None:
    monkeypatch.delenv("THREATLENS_RAG_VECTOR_PATH", raising=False)
    monkeypatch.setenv("THREATLENS_RAG_CHROMA_PATH", "data/rag/chroma_db")
    settings = RagSettings.from_environment()
    assert settings.vector_backend == "sqlite"
    assert settings.vector_path.as_posix().endswith("data/rag/vector_store.sqlite3")


def test_v0111_sqlite_vector_store_is_persistent_and_exact(tmp_path: Path) -> None:
    store = SQLiteVectorStore(path=tmp_path / "vectors.sqlite3", collection_name="security")
    provider = HashingEmbeddingProvider(dimensions=32)
    chunk = KnowledgeChunk(
        chunk_id="a" * 40,
        source_id="attack:T1059.001",
        title="PowerShell",
        source_kind="attack_technique",
        version="19.1",
        trust_tier="governed",
        section="document",
        text="PowerShell commands and scripts",
        source_reference="https://attack.mitre.org/techniques/T1059/001",
        content_sha256="b" * 64,
        metadata={"attack_id": "T1059.001"},
    )
    store.upsert([chunk], provider.embed([chunk.text]))
    reopened = SQLiteVectorStore(path=store.path, collection_name="security")
    assert reopened.count() == 1
    assert reopened.get_source_ids([chunk.source_id])[0].chunk.chunk_id == chunk.chunk_id


def test_v0111_setup_verify_and_local_ui_security_controls() -> None:
    setup = Path("scripts/setup.ps1").read_text(encoding="utf-8")
    verify = Path("scripts/verify.ps1").read_text(encoding="utf-8")
    for source in (setup, verify):
        assert "scripts.verify_dependency_security" in source
        assert "scripts.generate_dependency_attestation" in source

    streamlit_config = Path(".streamlit/config.toml").read_text(encoding="utf-8")
    run_script = Path("scripts/run.ps1").read_text(encoding="utf-8")
    assert 'address = "127.0.0.1"' in streamlit_config
    assert 'showErrorDetails = "none"' in streamlit_config
    assert "enableCORS = true" in streamlit_config
    assert "enableXsrfProtection = true" in streamlit_config
    assert "--server.address 127.0.0.1" in run_script


def test_v0111_source_sbom_matches_reviewed_direct_dependency_count() -> None:
    baseline = _load()
    expected = sum(len(baseline[name]) for name in ("build", "runtime", "development"))
    sbom = json.loads(Path("sbom/source-dependencies-v0.14.0.cdx.json").read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == expected


def test_v0111_runtime_attestation_is_release_excluded() -> None:
    inventory = Path("scripts/release_inventory.py").read_text(encoding="utf-8")
    assert 'relative.startswith("data/dependency_attestation/")' in inventory
    attestation = Path("scripts/generate_dependency_attestation.py").read_text(encoding="utf-8")
    assert "requirements-lock-windows-py311.txt" in attestation
    assert "cyclonedx-runtime-windows-py311.json" in attestation
    assert "record_sha256" in attestation


def test_v0111_current_verification_document_uses_correct_matrix() -> None:
    source = Path("docs/VERIFICATION_v0.11.1.md").read_text(encoding="utf-8")
    assert "v0.11 adaptive model runtime + UAT hardening | 28" in source
    assert "v0.11.1 security closure | 12" in source
    assert "**Total** | **246**" in source
    assert "Platform-independent total: **245**" in source


def test_v0111_third_party_notice_is_release_neutral() -> None:
    source = Path("docs/THIRD_PARTY_DATA_NOTICE.md").read_text(encoding="utf-8")
    assert "v0.7 source ZIP" not in source
    assert "immutable source release" in source
