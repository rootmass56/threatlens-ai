from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from database.service import ThreatLensPersistenceService
from database.session import SessionLocal
from rag.config import get_rag_settings
from rag.service import RagRuntime

DEFAULT_MODELS = ("qwen3:4b", "qwen3:8b")


def _select_case(title: str | None) -> dict:
    with SessionLocal() as session:
        cases = ThreatLensPersistenceService(session).list_incident_cases(limit=250)
    if not cases:
        raise SystemExit(
            "No persisted incidents are available. Run a ThreatLens demo analysis "
            "before benchmarking."
        )
    if title:
        lowered = title.casefold()
        for item in cases:
            if str(item.get("title") or "").casefold() == lowered:
                return item
        raise SystemExit(f"Incident title not found: {title}")
    # Prefer a case with richer stage/correlation context for model comparison.
    return max(
        cases,
        key=lambda item: (
            int(item.get("stage_count") or 0),
            int(item.get("alert_count") or 0),
            str(item.get("title") or ""),
        ),
    )


def _questions() -> tuple[tuple[str, str], ...]:
    return (
        (
            "incident_explanation",
            (
                "Explain why this incident matters. Cite only persisted ThreatLens "
                "evidence and keep unsupported claims explicit."
            ),
        ),
        (
            "hybrid_attack_explanation",
            (
                "For the ATT&CK techniques in this incident, explain separately what "
                "persisted ThreatLens evidence shows and what governed ATT&CK or "
                "detection-rule knowledge says. Cite both source types separately."
            ),
        ),
    )


def _run_query(*, model: str, incident_uuid: str, label: str, question: str) -> dict:
    settings = replace(get_rag_settings(), llm_model=model, deep_llm_model=model)
    runtime = RagRuntime(settings)
    with SessionLocal() as session:
        response = runtime.query(
            session,
            incident_uuid=incident_uuid,
            actor=f"rag-model-benchmark:{model}",
            question=question,
        )
        # Benchmark runs are intentionally read-only from an audit/history perspective.
        session.rollback()

    source_types = Counter(item.source_type for item in response.citations)
    return {
        "label": label,
        "question": question,
        "status": response.status.value,
        "grounding_score": response.grounding_score,
        "citation_count": len(response.citations),
        "citation_source_types": dict(sorted(source_types.items())),
        "technique_explanation_count": len(response.technique_explanations),
        "unsupported_citation_count": len(response.unsupported_citation_ids),
        "requested_mode": response.requested_mode.value,
        "resolved_mode": response.resolved_mode.value if response.resolved_mode else None,
        "requested_model": response.requested_model,
        "served_model": response.served_model,
        "fallback_used": response.fallback_used,
        "routing_score": response.routing_score,
        "routing_reasons": response.routing_reasons,
        "generation_latency_ms": response.generation_latency_ms,
        "retrieval": response.retrieval.model_dump(mode="json"),
        "latency_ms": response.total_latency_ms,
        "knowledge_version": response.knowledge_version,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark local Ollama models against the same live ThreatLens grounded-RAG "
            "incident questions. The script rolls back benchmark query-history/audit writes."
        )
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=list(DEFAULT_MODELS),
        help="Ollama model names to compare (default: qwen3:4b qwen3:8b).",
    )
    parser.add_argument(
        "--incident-title",
        help="Exact persisted incident title. If omitted, the richest current incident is used.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path.",
    )
    args = parser.parse_args()

    case = _select_case(args.incident_title)
    settings = get_rag_settings()
    payload: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "incident_uuid": case["incident_uuid"],
        "incident_title": case["title"],
        "embedding_model": settings.embedding_model,
        "vector_backend": settings.vector_backend,
        "models": {},
    }

    for model in list(dict.fromkeys(args.models)):
        model_settings = replace(settings, llm_model=model, deep_llm_model=model)
        runtime = RagRuntime(model_settings)
        health = runtime.health()
        model_result: dict[str, object] = {
            "health": health.model_dump(mode="json"),
            "queries": [],
        }
        if health.status != "ready":
            model_result["skipped"] = (
                "Model/runtime is not ready. Install the model in Ollama and ensure the "
                "advanced knowledge index is built before benchmarking."
            )
        else:
            for label, question in _questions():
                try:
                    model_result["queries"].append(
                        _run_query(
                            model=model,
                            incident_uuid=case["incident_uuid"],
                            label=label,
                            question=question,
                        )
                    )
                except Exception as error:  # benchmark must report, not hide, runtime failures
                    model_result["queries"].append(
                        {
                            "label": label,
                            "question": question,
                            "error": str(error),
                        }
                    )
        payload["models"][model] = model_result

    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote benchmark report: {args.output}")


if __name__ == "__main__":
    main()
