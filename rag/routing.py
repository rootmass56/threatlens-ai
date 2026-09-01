from __future__ import annotations

from collections.abc import Mapping

from rag.models import RagAnalysisMode, RagQueryPlan, RagRoutingDecision

_COMPARISON_TERMS = (
    "compare",
    "contrast",
    "separately",
    "distinguish",
    "difference between",
)
_SEQUENCE_TERMS = (
    "timeline",
    "progression",
    "sequence",
    "multi-stage",
    "multistage",
    "attack chain",
    "correlate",
    "relationship",
    "across sources",
    "cross-source",
)


def _count(details: Mapping[str, object], key: str) -> int:
    value = details.get(key)
    return len(value) if isinstance(value, list) else 0


class AdaptiveModelRouter:
    """Deterministic, auditable model routing; no LLM is used to choose an LLM."""

    def __init__(self, *, deep_threshold: int = 5) -> None:
        self.deep_threshold = max(int(deep_threshold), 1)

    def route(
        self,
        *,
        requested_mode: RagAnalysisMode,
        question: str,
        plan: RagQueryPlan,
        details: Mapping[str, object],
        standard_model: str,
        deep_model: str,
    ) -> RagRoutingDecision:
        if requested_mode == RagAnalysisMode.STANDARD:
            return RagRoutingDecision(
                requested_mode=requested_mode,
                resolved_mode=RagAnalysisMode.STANDARD,
                requested_model=standard_model,
                complexity_score=0,
                reasons=["analyst_override_standard"],
            )
        if requested_mode == RagAnalysisMode.DEEP:
            return RagRoutingDecision(
                requested_mode=requested_mode,
                resolved_mode=RagAnalysisMode.DEEP,
                requested_model=deep_model,
                complexity_score=self.deep_threshold,
                reasons=["analyst_override_deep"],
            )

        score = 0
        reasons: list[str] = []
        lowered = question.casefold()

        if plan.requires_source_separation:
            score += 4
            reasons.append("evidence_knowledge_source_separation")
        elif plan.requires_governed_knowledge:
            score += 2
            reasons.append("governed_knowledge_required")

        if plan.requires_inference_separation:
            score += 1
            reasons.append("fact_inference_separation")

        if len(plan.attack_ids) >= 3:
            score += 4
            reasons.append("three_or_more_attack_techniques")
        elif len(plan.attack_ids) == 2:
            score += 2
            reasons.append("multiple_attack_techniques")

        if any(term in lowered for term in _COMPARISON_TERMS):
            score += 2
            reasons.append("comparative_reasoning")
        if any(term in lowered for term in _SEQUENCE_TERMS):
            score += 2
            reasons.append("sequence_or_cross_source_reasoning")

        alert_count = _count(details, "alerts")
        event_count = _count(details, "events")
        if alert_count >= 6:
            score += 1
            reasons.append("high_alert_context")
        if event_count >= 12:
            score += 1
            reasons.append("high_event_context")

        resolved = (
            RagAnalysisMode.DEEP if score >= self.deep_threshold else RagAnalysisMode.STANDARD
        )
        if not reasons:
            reasons.append("routine_incident_question")
        model = deep_model if resolved == RagAnalysisMode.DEEP else standard_model
        return RagRoutingDecision(
            requested_mode=requested_mode,
            resolved_mode=resolved,
            requested_model=model,
            complexity_score=score,
            reasons=reasons,
        )
