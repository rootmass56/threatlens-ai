from __future__ import annotations

import json

from rag.config import RagSettings
from rag.degraded import deterministic_model_name
from rag.model_profiles import build_model_profiles
from rag.models import RagAnalysisMode, RagQueryPlan
from rag.response_policy import enforce_conservative_incident_language
from rag.routing import AdaptiveModelRouter


def main() -> None:
    settings = RagSettings.from_environment()
    profiles = build_model_profiles(settings)
    router = AdaptiveModelRouter(deep_threshold=settings.auto_deep_threshold)

    routine = router.route(
        requested_mode=RagAnalysisMode.AUTO,
        question="Why does this incident matter?",
        plan=RagQueryPlan(),
        details={"alerts": [], "events": []},
        standard_model=profiles[RagAnalysisMode.STANDARD].model_name,
        deep_model=profiles[RagAnalysisMode.DEEP].model_name,
    )
    hybrid = router.route(
        requested_mode=RagAnalysisMode.AUTO,
        question=(
            "Compare T1110.001, T1059.001 and T1003.001 and explain persisted evidence "
            "and governed ATT&CK knowledge separately."
        ),
        plan=RagQueryPlan(
            attack_ids=["T1110.001", "T1059.001", "T1003.001"],
            exact_source_ids=[
                "attack:T1110.001",
                "attack:T1059.001",
                "attack:T1003.001",
            ],
            requires_governed_knowledge=True,
            requires_source_separation=True,
        ),
        details={"alerts": [{}] * 8, "events": [{}] * 16},
        standard_model=profiles[RagAnalysisMode.STANDARD].model_name,
        deep_model=profiles[RagAnalysisMode.DEEP].model_name,
    )
    manual_deep = router.route(
        requested_mode=RagAnalysisMode.DEEP,
        question="Summarize this incident.",
        plan=RagQueryPlan(),
        details={},
        standard_model=profiles[RagAnalysisMode.STANDARD].model_name,
        deep_model=profiles[RagAnalysisMode.DEEP].model_name,
    )

    checks = {
        "routine_auto_routes_standard": routine.resolved_mode == RagAnalysisMode.STANDARD,
        "complex_auto_routes_deep": hybrid.resolved_mode == RagAnalysisMode.DEEP,
        "manual_deep_override": manual_deep.resolved_mode == RagAnalysisMode.DEEP,
        "standard_model_profile": profiles[RagAnalysisMode.STANDARD].model_name == "qwen3.5:4b",
        "deep_model_profile": profiles[RagAnalysisMode.DEEP].model_name == "qwen3.5:9b",
        "deep_output_budget": profiles[RagAnalysisMode.DEEP].num_predict >= 1400,
        "deep_context_budget": profiles[RagAnalysisMode.DEEP].num_ctx >= 8192,
        "fallback_enabled": settings.fallback_to_standard,
        "long_failure_circuit_breaker": (settings.standard_fallback_max_primary_seconds > 0),
        "deterministic_fallback_present": (
            deterministic_model_name() == "deterministic-grounded-fallback"
        ),
        "deep_timeout_bounded": profiles[RagAnalysisMode.DEEP].read_timeout_seconds <= 600,
        "conservative_claim_hardening": "credential theft"
        not in (
            enforce_conservative_incident_language(
                "indicating potential credential theft and lateral movement"
            ).casefold()
        ),
        "technique_binding_hardening_present": (
            __import__("pathlib")
            .Path("rag/grounding.py")
            .read_text(encoding="utf-8")
            .find("build_technique_knowledge_bindings")
            >= 0
        ),
        "alias_prose_hardening_present": (
            __import__("pathlib")
            .Path("rag/llm.py")
            .read_text(encoding="utf-8")
            .find("temporary C# aliases")
            >= 0
        ),
    }
    payload = {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "routine_route": routine.model_dump(mode="json"),
        "hybrid_route": hybrid.model_dump(mode="json"),
        "profiles": {
            mode.value: {
                "model": profile.model_name,
                "num_ctx": profile.num_ctx,
                "num_predict": profile.num_predict,
                "read_timeout_seconds": profile.read_timeout_seconds,
            }
            for mode, profile in profiles.items()
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if payload["status"] != "passed":
        raise SystemExit("Adaptive RAG verification failed.")


if __name__ == "__main__":
    main()
