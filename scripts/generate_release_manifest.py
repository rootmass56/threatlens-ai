from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from api.version import THREATLENS_VERSION
from scripts.openapi_contract import canonicalize_openapi
from scripts.release_inventory import CURRENT_MANIFEST, ROOT_DIR, file_record, release_paths

OUTPUT_PATH = ROOT_DIR / CURRENT_MANIFEST
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def main() -> None:
    os.environ.setdefault(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api.main import app
    from api.rbac import ROLE_DEFINITIONS

    schema = canonicalize_openapi(app.openapi())
    paths = schema.get("paths", {})
    operation_count = sum(
        1 for path_item in paths.values() for method in path_item if method.lower() in HTTP_METHODS
    )
    records = [file_record(path) for path in release_paths()]
    payload = {
        "product": "ThreatLens AI",
        "version": THREATLENS_VERSION,
        "release_title": "v0.14.0 Batch 7 Operational Hardening",
        "published_project_release": "v1.0.0",
        "base_release": "v0.13.0",
        "generated_utc": datetime.now(UTC).isoformat(),
        "python_target": "3.11.x",
        "alembic_head": "b7f1c2d30001",
        "api": {
            "title": schema.get("info", {}).get("title"),
            "version": schema.get("info", {}).get("version"),
            "prefix": "/api/v1",
            "openapi_paths": len(paths),
            "openapi_operations": operation_count,
            "protected_openapi_endpoint": "/api/v1/system/openapi",
            "development_docs_enabled_by_default": False,
            "rag_query_endpoint": "/api/v1/incidents/{incident_uuid}/assistant/jobs",
            "rag_history_endpoint": "/api/v1/incidents/{incident_uuid}/assistant/history",
            "rag_health_endpoint": "/api/v1/rag/health",
        },
        "roles": list(ROLE_DEFINITIONS),
        "governed_test_matrix": {
            "collected_tests": 334,
            "validation_command": "python -m pytest -q",
            "runtime_pins": {
                "streamlit": "1.64.0",
                "fastapi": "0.141.1",
                "starlette": "1.7.0",
                "uvicorn": "0.53.0",
                "argon2-cffi": "25.1.0",
                "PyJWT": "2.15.0",
                "python-multipart": "0.0.32",
                "email-validator": "2.3.0",
                "pandas": "2.2.3",
                "plotly": "6.5.2",
                "reportlab": "5.0.1",
                "python-dotenv": "1.2.3",
                "pydantic": "2.13.5",
                "requests": "2.34.2",
                "sqlalchemy": "2.0.54",
                "alembic": "1.20.0",
                "psycopg": "3.3.6",
                "pgvector": "0.5.0",
                "PyYAML": "6.0.3",
                "pytest": "9.1.1",
                "pytest-cov": "7.1.0",
                "httpx2": "2.13.1",
                "ruff": "0.16.8",
                "pip": "26.2.1",
                "setuptools": "84.0.0",
                "wheel": "0.48.0",
            },
        },
        "rag_controls": {
            "deterministic_detection_remains_authoritative": True,
            "incident_context_is_server_compiled": True,
            "rag_query_requires_authorization": True,
            "rag_management_is_privileged": True,
            "streamlit_uses_fastapi_boundary_only": True,
            "approved_knowledge_sources_are_allowlisted": True,
            "knowledge_sources_are_sha256_versioned": True,
            "chunk_ids_are_deterministic": True,
            "incremental_indexing_is_hash_based": True,
            "retrieved_text_is_treated_as_untrusted_data": True,
            "prompt_injection_patterns_are_blocked": True,
            "unknown_model_citations_are_rejected": True,
            "citation_planes_are_enforced": True,
            "hybrid_exact_and_semantic_retrieval": True,
            "attack_id_exact_retrieval": True,
            "cross_incident_named_requests_are_blocked": True,
            "missing_specific_facts_are_refused_before_llm": True,
            "incident_and_governed_knowledge_are_separated": True,
            "attribution_requires_direct_evidence": True,
            "llm_unavailability_degrades_gracefully": True,
            "rag_queries_are_persisted_and_audited": True,
            "rag_runtime_storage_is_release_excluded": True,
            "external_live_runtime_gate_is_configurable": True,
            "deterministic_adaptive_model_routing": True,
            "analyst_auto_standard_deep_modes": True,
            "deep_to_standard_fallback_is_transparent": True,
            "fallback_answers_are_revalidated": True,
            "routing_and_generation_latency_are_audited": True,
            "technique_explanations_are_deduplicated": True,
            "technique_knowledge_citations_are_attack_id_bound": True,
            "internal_prompt_aliases_are_removed_from_prose": True,
            "fallback_errors_are_analyst_safe": True,
            "fact_inference_separation_is_supported": True,
            "incident_claim_language_is_conservatively_hardened": True,
            "openapi_snapshot_is_canonicalized_for_binary_upload_dialect": True,
            "threatlens_owned_sqlite_vector_backend": True,
            "production_pgvector_backend": True,
            "authenticated_remote_ollama_supported": True,
            "react_vite_production_soc_ui": True,
            "react_streamlit_feature_parity_governed": True,
            "safe_v0111_operational_data_migration": True,
            "postgresql_production_persistence": True,
            "network_vector_database_dependency_removed": True,
            "dependency_security_baseline_enforced": True,
            "runtime_transitive_lock_and_sbom_attested": True,
        },
        "validated_deterministic_controls": {
            "governed_rules": 46,
            "fixture_cases": 138,
            "linux_baseline": "9 events / 4 alerts / 1 incident / 0 quarantined",
            "multisource_baseline": "22 events / 8 alerts / 2 incidents / 0 quarantined",
            "attack_release": "v19.1 Enterprise, Mobile and ICS",
        },
        "hashing_policy": {
            "algorithm": "SHA-256",
            "utf8_text_newlines": "canonical LF",
            "binary_files": "byte-for-byte",
        },
        "manifest_scope": (
            "The manifest inventories every releasable source/configuration/documentation file "
            "present in the release tree except this manifest itself. Runtime secrets, virtual "
            "environments, caches, databases, downloaded ATT&CK bundles, generated reports and "
            "runtime RAG vector/index data are intentionally excluded."
        ),
        "excluded_runtime_material": [
            ".git",
            ".venv",
            ".env and .env.* except .env.example",
            ".streamlit/secrets.toml",
            "Python/Pytest/Ruff caches",
            "SQLite databases and WAL/SHM files",
            "bootstrap administrator credentials",
            "downloaded ATT&CK STIX bundles and generated metadata",
            "runtime SQLite vector/index data under data/rag",
            "runtime transitive dependency lock/SBOM data under data/dependency_attestation",
            "generated reports/exports",
            "packaging ZIP files",
        ],
        "files": records,
    }
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Generated {CURRENT_MANIFEST}: {len(records)} releasable files inventoried.")


if __name__ == "__main__":
    main()
