from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.pipeline import analyze_linux_auth_log
from database.base import Base
from database.models import AttackCatalogVersionModel, AttackObjectModel
from database.service import ThreatLensPersistenceService
from rag.context import IncidentContextCompiler
from rag.embeddings import HashingEmbeddingProvider
from rag.grounding import build_citation_catalog, validate_grounding_detailed
from rag.indexing import KnowledgeIndexService
from rag.models import GeneratedInvestigation, TechniqueExplanation
from rag.planning import build_query_plan
from rag.retrieval import KnowledgeRetriever
from rag.vector_store import MemoryVectorStore


def _seed_attack_catalog(session) -> None:
    catalog = AttackCatalogVersionModel(
        domain="enterprise-attack",
        display_name="Enterprise ATT&CK",
        version="19.1",
        collection_id="verification-enterprise",
        source_url="https://attack.mitre.org/",
        source_modified="2026-05-12T14:00:00.188Z",
        content_sha256="a" * 64,
        object_count=1,
        active_object_count=1,
        relationship_count=0,
        tactic_count=1,
        technique_count=1,
        subtechnique_count=1,
        object_type_counts_json={"attack-pattern": 1},
        metadata_json={},
        is_active=True,
    )
    session.add(catalog)
    session.flush()
    session.add(
        AttackObjectModel(
            catalog_version_id=catalog.id,
            stix_id="attack-pattern--verification-t1110-001",
            object_type="attack-pattern",
            attack_id="T1110.001",
            name="Password Guessing",
            description=(
                "Adversaries may guess passwords to obtain access to accounts when "
                "credential material is not otherwise available."
            ),
            active=True,
            is_subtechnique=True,
            parent_attack_id="T1110",
            tactic_shortnames_json=["credential-access"],
            platforms_json=["Linux", "Windows"],
            external_url="https://attack.mitre.org/techniques/T1110/001/",
            raw_json={},
        )
    )
    session.flush()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="threatlens-advanced-rag-") as temporary:
        temp = Path(temporary)
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

        with factory() as session:
            _seed_attack_catalog(session)
            log_path = Path("data/sample_logs/auth_sample.log")
            raw = log_path.read_text(encoding="utf-8-sig")
            pipeline = analyze_linux_auth_log(raw)
            persistence = ThreatLensPersistenceService(session)
            persistence.persist_analysis(
                analysis_name="advanced RAG verification",
                source_type="linux_auth",
                original_filename=log_path.name,
                raw_content=raw,
                events_df=pipeline.events_df,
                alerts_df=pipeline.alerts_df,
                incidents_df=pipeline.incidents_df,
                actor="advanced-rag-verifier",
            )
            session.flush()

            case = persistence.list_incident_cases()[0]
            details = persistence.get_incident_details(case["incident_uuid"])
            assert details is not None

            provider = HashingEmbeddingProvider(dimensions=64)
            store = MemoryVectorStore()
            indexer = KnowledgeIndexService(
                vector_store=store,
                embedding_provider=provider,
                manifest_path=temp / "index_manifest.json",
                root=Path.cwd(),
                embedding_batch_size=64,
            )
            index_result = indexer.index(session, force=True)
            assert index_result.status == "indexed"
            assert index_result.documents_seen >= 48

            question = (
                "For T1110.001 explain separately what persisted incident evidence "
                "shows and what governed ATT&CK or detection-rule knowledge says. "
                "Cite both separately."
            )
            plan = build_query_plan(
                question,
                details=details,
                incidents=persistence.list_incident_cases(),
            )
            assert plan.requires_governed_knowledge
            assert plan.requires_source_separation
            assert "attack:T1110.001" in plan.exact_source_ids

            retrieved, diagnostics = KnowledgeRetriever(
                vector_store=store,
                embedding_provider=provider,
            ).retrieve(
                question,
                top_k=3,
                minimum_relevance=0.0,
                exact_source_ids=plan.exact_source_ids,
                exact_limit=8,
            )
            assert diagnostics.missing_source_ids == []
            assert any(item.chunk.source_id == "attack:T1110.001" for item in retrieved)
            assert any(item.chunk.source_kind == "detection_rule" for item in retrieved)

            context = IncidentContextCompiler(max_chars=6500).compile(
                details,
                focus_attack_ids=["T1110.001"],
                question=question,
            )
            evidence_id = next(
                item.citation_id for item in context.citations if item.source_type == "alert"
            )
            attack_item = next(
                item for item in retrieved if item.chunk.source_id == "attack:T1110.001"
            )
            kb_id = f"KB:{attack_item.chunk.chunk_id}"
            catalog = build_citation_catalog(context, retrieved)
            generated = GeneratedInvestigation(
                assessment="The incident contains password-guessing evidence.",
                assessment_citation_ids=["INCIDENT"],
                technique_explanations=[
                    TechniqueExplanation(
                        technique_id="T1110.001",
                        technique_name="Password Guessing",
                        observed_evidence=(
                            "Repeated authentication failures are present in the "
                            "persisted incident."
                        ),
                        evidence_citation_ids=[evidence_id],
                        governed_explanation=(
                            "The governed ATT&CK record defines T1110.001 as Password Guessing."
                        ),
                        knowledge_citation_ids=[kb_id],
                    )
                ],
                limitations=[],
                confidence="high",
            )
            grounding = validate_grounding_detailed(generated, catalog)
            assert grounding.score == 1.0
            assert grounding.invalid_citation_ids == []
            assert grounding.technique_explanations[0].evidence_citation_ids == [evidence_id]
            assert grounding.technique_explanations[0].knowledge_citation_ids == [kb_id]

            other_title = "Different Authorized Incident"
            mismatch = build_query_plan(
                f'Tell me everything from the "{other_title}" incident.',
                details=details,
                incidents=[case, {"title": other_title}],
            )
            assert mismatch.incident_mismatch

            missing = build_query_plan(
                "What malware family, SHA-256 hash, and threat group are present?",
                details=details,
                incidents=[case],
            )
            assert set(missing.missing_fact_types) == {
                "malware_family",
                "sha256",
                "threat_group",
            }

            print(
                json.dumps(
                    {
                        "status": "passed",
                        "documents_seen": index_result.documents_seen,
                        "indexed_chunks": index_result.indexed_chunks,
                        "exact_source_ids": plan.exact_source_ids,
                        "exact_match_count": diagnostics.exact_match_count,
                        "source_kind_counts": diagnostics.source_kind_counts,
                        "grounding_score": grounding.score,
                        "citation_plane_validation": "passed",
                        "cross_incident_mismatch_detection": "passed",
                        "missing_specific_fact_detection": "passed",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        engine.dispose()


if __name__ == "__main__":
    main()
