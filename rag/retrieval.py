
from __future__ import annotations

import time
from collections import Counter

from rag.embeddings import EmbeddingProvider
from rag.models import RetrievalDiagnostics, RetrievedChunk
from rag.security import contains_instruction_injection
from rag.vector_store import VectorStore


class KnowledgeRetriever:
    def __init__(self, *, vector_store: VectorStore, embedding_provider: EmbeddingProvider) -> None:
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider

    @staticmethod
    def _safe_chunk(item: RetrievedChunk) -> bool:
        return not contains_instruction_injection(item.chunk.text)

    def retrieve(
        self,
        question: str,
        *,
        top_k: int,
        minimum_relevance: float,
        exact_source_ids: list[str] | None = None,
        exact_limit: int = 8,
    ) -> tuple[list[RetrievedChunk], RetrievalDiagnostics]:
        """Hybrid retrieval: exact governed-source lookup + dense semantic retrieval."""

        started = time.perf_counter()
        ready, _ = self.vector_store.ready()
        requested_source_ids = list(dict.fromkeys(exact_source_ids or []))
        if not ready or self.vector_store.count() == 0:
            return [], RetrievalDiagnostics(
                requested_top_k=top_k,
                retrieved_count=0,
                accepted_count=0,
                minimum_relevance=minimum_relevance,
                requested_source_ids=requested_source_ids,
                missing_source_ids=requested_source_ids,
                retrieval_latency_ms=(time.perf_counter() - started) * 1000,
            )

        exact: list[RetrievedChunk] = []
        if requested_source_ids:
            raw_exact = self.vector_store.get_source_ids(requested_source_ids)
            by_source: dict[str, list[RetrievedChunk]] = {}
            for item in raw_exact:
                by_source.setdefault(item.chunk.source_id, []).append(item)

            # Exact retrieval is source-oriented rather than chunk-oriented. A long
            # ATT&CK document can span multiple chunks; allowing those chunks to
            # consume the exact-match limit can starve later explicitly requested
            # techniques/rules. Keep one representative chunk per requested source
            # so every planned source gets a fair slot.
            source_limit = max(int(exact_limit), 1)
            for source_id in requested_source_ids[:source_limit]:
                candidates = by_source.get(source_id) or []
                if not candidates:
                    continue
                representative = max(
                    candidates,
                    key=lambda item: (
                        item.chunk.text.startswith(("MITRE ATT&CK ", "Detection:")),
                        len(item.chunk.text),
                        item.chunk.chunk_id,
                    ),
                )
                exact.append(representative)

        embedding = self.embedding_provider.embed([question])[0]
        semantic = self.vector_store.query(embedding, top_k=max(int(top_k), 1))

        blocked = 0
        accepted: list[RetrievedChunk] = []
        seen_chunks: set[str] = set()
        seen_semantic_sources: set[str] = set()

        # Exact matches are authoritative query-plan targets and are considered first.
        for item in exact:
            if not self._safe_chunk(item):
                blocked += 1
                continue
            if item.chunk.chunk_id in seen_chunks:
                continue
            seen_chunks.add(item.chunk.chunk_id)
            accepted.append(
                RetrievedChunk(
                    chunk=item.chunk,
                    relevance=1.0,
                    rank=len(accepted) + 1,
                )
            )

        for item in semantic:
            if item.relevance < minimum_relevance:
                continue
            if not self._safe_chunk(item):
                blocked += 1
                continue
            if item.chunk.chunk_id in seen_chunks:
                continue
            # Keep semantic retrieval diverse. Exact matches are exempt because they
            # were deliberately requested by the query planner.
            if item.chunk.source_id in seen_semantic_sources and len(accepted) >= max(
                3, top_k // 2
            ):
                continue
            seen_semantic_sources.add(item.chunk.source_id)
            seen_chunks.add(item.chunk.chunk_id)
            accepted.append(
                RetrievedChunk(
                    chunk=item.chunk,
                    relevance=item.relevance,
                    rank=len(accepted) + 1,
                )
            )

        found_source_ids = {item.chunk.source_id for item in exact}
        missing_source_ids = [
            source_id for source_id in requested_source_ids if source_id not in found_source_ids
        ]
        source_kind_counts = dict(Counter(item.chunk.source_kind for item in accepted))

        return accepted, RetrievalDiagnostics(
            requested_top_k=top_k,
            retrieved_count=len(exact) + len(semantic),
            accepted_count=len(accepted),
            minimum_relevance=minimum_relevance,
            blocked_injection_chunks=blocked,
            semantic_count=len(semantic),
            exact_match_count=len(exact),
            source_kind_counts=source_kind_counts,
            requested_source_ids=requested_source_ids,
            missing_source_ids=missing_source_ids,
            retrieval_latency_ms=(time.perf_counter() - started) * 1000,
        )
