
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from rag.embeddings import EmbeddingProvider
from rag.knowledge import chunk_document, collect_documents
from rag.models import RagIndexResult
from rag.vector_store import VectorStore


class KnowledgeIndexService:
    def __init__(
        self,
        *,
        vector_store: VectorStore,
        embedding_provider: EmbeddingProvider,
        manifest_path: Path,
        root: Path,
        embedding_batch_size: int = 32,
    ) -> None:
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider
        self.manifest_path = manifest_path
        self.root = root
        self.embedding_batch_size = max(int(embedding_batch_size), 1)
        self._lock = threading.RLock()

    @staticmethod
    def _document_hash(document) -> str:
        payload = json.dumps(
            {
                "source_id": document.source_id,
                "title": document.title,
                "version": document.version,
                "text": document.text,
                "metadata": document.metadata,
            },
            sort_keys=True,
            default=str,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _read_manifest(self) -> dict:
        read_durable = getattr(self.vector_store, "read_manifest", None)
        if callable(read_durable):
            payload = read_durable()
            if isinstance(payload, dict):
                return payload
        if not self.manifest_path.is_file():
            return {"sources": {}}
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {"sources": {}}
        except (OSError, json.JSONDecodeError):
            return {"sources": {}}

    def _write_manifest(self, payload: dict) -> None:
        write_durable = getattr(self.vector_store, "write_manifest", None)
        if callable(write_durable):
            write_durable(payload)
        try:
            self._write_manifest(payload)
        except OSError:
            if not callable(write_durable):
                raise

    def _unavailable(self, detail: str) -> RagIndexResult:
        ready, _ = self.vector_store.ready()
        indexed = self.vector_store.count() if ready else 0
        return RagIndexResult(
            status="unavailable",
            documents_seen=0,
            documents_added_or_updated=0,
            documents_removed=0,
            chunks_upserted=0,
            chunks_deleted=0,
            indexed_chunks=indexed,
            knowledge_version="unavailable",
            manifest_path=None,
            details=[detail],
        )

    def index(self, session: Session, *, force: bool = False) -> RagIndexResult:
        with self._lock:
            ready, detail = self.vector_store.ready()
            if not ready:
                return self._unavailable(detail or "The configured vector store is unavailable.")
            emb_reachable, emb_available, emb_detail = self.embedding_provider.health()
            if not emb_reachable or not emb_available:
                return self._unavailable(
                    emb_detail or "The configured embedding provider/model is unavailable."
                )

            documents = collect_documents(session, self.root)
            current = {document.source_id: document for document in documents}
            old = self._read_manifest().get("sources") or {}
            current_hashes = {
                source_id: self._document_hash(document) for source_id, document in current.items()
            }
            changed = [
                source_id
                for source_id, digest in current_hashes.items()
                if force or (old.get(source_id) or {}).get("document_sha256") != digest
            ]
            removed = sorted(set(old) - set(current))
            chunks = []
            chunk_counts: dict[str, int] = {}
            for source_id in changed:
                source_chunks = chunk_document(current[source_id])
                chunks.extend(source_chunks)
                chunk_counts[source_id] = len(source_chunks)

            # Compute embeddings before deleting the prior source versions. If the external
            # embedding service is unavailable, the last known-good index remains intact and
            # the unchanged manifest causes a safe retry on the next indexing attempt.
            embedded_batches: list[tuple[list, list[list[float]]]] = []
            total_batches = (
                (len(chunks) + self.embedding_batch_size - 1) // self.embedding_batch_size
                if chunks
                else 0
            )
            if chunks:
                print(
                    f"RAG indexing: {len(chunks)} chunks across {total_batches} "
                    f"embedding batches (batch size={self.embedding_batch_size}).",
                    flush=True,
                )
            for batch_number, start in enumerate(
                range(0, len(chunks), self.embedding_batch_size), start=1
            ):
                batch = chunks[start : start + self.embedding_batch_size]
                print(
                    f"Embedding batch {batch_number}/{total_batches} ({len(batch)} chunks)...",
                    flush=True,
                )
                embeddings = self.embedding_provider.embed([chunk.text for chunk in batch])
                if len(embeddings) != len(batch):
                    raise RuntimeError("Embedding provider returned an unexpected vector count.")
                embedded_batches.append((batch, embeddings))
                print(
                    f"Embedding batch {batch_number}/{total_batches}: complete",
                    flush=True,
                )

            delete_targets = sorted(set(changed) | set(removed))
            if force:
                deleted = self.vector_store.clear()
            else:
                deleted = (
                    self.vector_store.delete_source_ids(delete_targets) if delete_targets else 0
                )
            for batch, embeddings in embedded_batches:
                self.vector_store.upsert(batch, embeddings)

            sources = {}
            for source_id in sorted(current):
                existing_chunk_count = (old.get(source_id) or {}).get("chunk_count")
                sources[source_id] = {
                    "document_sha256": current_hashes[source_id],
                    "title": current[source_id].title,
                    "source_kind": current[source_id].source_kind,
                    "version": current[source_id].version,
                    "source_reference": current[source_id].source_reference,
                    "chunk_count": int(chunk_counts.get(source_id, existing_chunk_count or 0)),
                }
            version_payload = "\n".join(
                f"{source_id}:{record['document_sha256']}" for source_id, record in sources.items()
            )
            knowledge_version = hashlib.sha256(version_payload.encode("utf-8")).hexdigest()[:16]
            payload = {
                "schema_version": "0.12.0",
                "knowledge_version": knowledge_version,
                "embedding_model": self.embedding_provider.model_name,
                "indexed_utc": datetime.now(UTC).isoformat(),
                "indexed_chunks": self.vector_store.count(),
                "sources": sources,
            }
            self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.manifest_path.with_suffix(self.manifest_path.suffix + ".tmp")
            temporary.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.replace(self.manifest_path)
            status = "indexed" if changed or removed else "unchanged"
            return RagIndexResult(
                status=status,
                documents_seen=len(documents),
                documents_added_or_updated=len(changed),
                documents_removed=len(removed),
                chunks_upserted=len(chunks),
                chunks_deleted=deleted,
                indexed_chunks=self.vector_store.count(),
                knowledge_version=knowledge_version,
                manifest_path=self.manifest_path.as_posix(),
            )

    def status(self) -> dict:
        with self._lock:
            payload = self._read_manifest()
            ready, detail = self.vector_store.ready()
            return {
                "knowledge_version": payload.get("knowledge_version"),
                "embedding_model": payload.get("embedding_model"),
                "indexed_utc": payload.get("indexed_utc"),
                "indexed_chunks": self.vector_store.count() if ready else 0,
                "source_count": len(payload.get("sources") or {}),
                "manifest_path": self.manifest_path.as_posix(),
                "vector_ready": ready,
                "detail": detail,
            }
