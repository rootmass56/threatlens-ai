
from __future__ import annotations

import re
from collections.abc import Iterable

from rag.models import (
    GeneratedInvestigation,
    GroundedClaim,
    IncidentCitation,
    IncidentContext,
    RagQueryPlan,
    RetrievedChunk,
    TechniqueExplanation,
)

_DETERMINISTIC_MODEL_NAME = "deterministic-grounded-fallback"


def deterministic_model_name() -> str:
    return _DETERMINISTIC_MODEL_NAME


def _compact(text: str, limit: int = 420) -> str:
    cleaned = " ".join(str(text or "").split()).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(limit - 1, 1)].rstrip() + "â€¦"


def _knowledge_attack_ids(item: RetrievedChunk) -> set[str]:
    metadata = item.chunk.metadata or {}
    values: set[str] = set()
    direct = str(metadata.get("attack_id") or "").upper().strip()
    if direct:
        values.add(direct)
    values.update(
        str(value).upper().strip()
        for value in metadata.get("attack_ids") or []
        if str(value).strip()
    )
    return values


def _evidence_candidates(
    citations: Iterable[IncidentCitation],
    attack_id: str,
) -> list[IncidentCitation]:
    requested = attack_id.upper()
    ranked: list[tuple[int, int, IncidentCitation]] = []
    priority = {
        "alert": 0,
        "event": 1,
        "relationship": 2,
        "incident": 3,
        "entity": 4,
        "evidence": 5,
    }
    for index, citation in enumerate(citations):
        haystack = f"{citation.title} {citation.snippet}".upper()
        if requested not in haystack:
            continue
        ranked.append((priority.get(citation.source_type, 9), index, citation))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ranked]


def _knowledge_candidates(
    knowledge: Iterable[RetrievedChunk],
    attack_id: str,
) -> list[RetrievedChunk]:
    requested = attack_id.upper()
    ranked: list[tuple[int, int, RetrievedChunk]] = []
    for index, item in enumerate(knowledge):
        if requested not in _knowledge_attack_ids(item):
            continue
        source_priority = 0 if item.chunk.source_kind == "attack_technique" else 1
        ranked.append((source_priority, index, item))
    ranked.sort(key=lambda entry: (entry[0], entry[1]))
    return [entry[2] for entry in ranked]


def _technique_name(item: RetrievedChunk, attack_id: str) -> str | None:
    title = _compact(item.chunk.title, 180)
    if title.upper().startswith(attack_id.upper()):
        remainder = title[len(attack_id) :].strip(" -â€”:")
        return remainder or None
    return title or None


def _governed_summary(item: RetrievedChunk, attack_id: str) -> str:
    text = _compact(item.chunk.text, 800)
    description = re.split(r"\bDescription:\s*", text, maxsplit=1, flags=re.I)
    if len(description) == 2:
        text = description[1]
    sentence = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0].strip()
    if sentence:
        return _compact(sentence, 520)
    return f"The governed source {item.chunk.title} explicitly describes or maps to {attack_id}."


def build_deterministic_investigation(
    *,
    context: IncidentContext,
    knowledge: list[RetrievedChunk],
    plan: RagQueryPlan,
) -> GeneratedInvestigation:
    """Build a bounded, citation-ready response without an LLM.

    This path is intentionally conservative. It is used only after local model
    generation cannot complete, so the analyst still receives source-linked
    evidence rather than an ungrounded or empty answer.
    """

    incident_by_id = {citation.citation_id: citation for citation in context.citations}
    technique_explanations: list[TechniqueExplanation] = []
    findings: list[GroundedClaim] = []
    actions: list[GroundedClaim] = []
    assessment_ids: list[str] = ["INCIDENT"] if "INCIDENT" in incident_by_id else []

    for attack_id in plan.attack_ids:
        evidence = _evidence_candidates(context.citations, attack_id)
        governed = _knowledge_candidates(knowledge, attack_id)
        if not evidence or not governed:
            continue

        evidence_ids = [item.citation_id for item in evidence[:2]]
        knowledge_item = governed[0]
        knowledge_id = f"KB:{knowledge_item.chunk.chunk_id}"
        evidence_title = _compact(evidence[0].title, 220)
        technique_name = _technique_name(knowledge_item, attack_id)

        observed = f"ThreatLens persisted evidence mapped to {attack_id}: {evidence_title}."
        governed_text = _governed_summary(knowledge_item, attack_id)
        inference = (
            "Analyst inference: the mapped evidence may be relevant to the incident, "
            "but it does not establish causation, successful compromise, credential "
            "theft, credential dumping, lateral movement, or adversary intent."
        )
        technique_explanations.append(
            TechniqueExplanation(
                technique_id=attack_id,
                technique_name=technique_name,
                observed_evidence=observed,
                evidence_citation_ids=evidence_ids,
                governed_explanation=governed_text,
                knowledge_citation_ids=[knowledge_id],
                analyst_inference=inference,
            )
        )
        findings.append(
            GroundedClaim(
                text=observed,
                citation_ids=evidence_ids,
            )
        )
        actions.append(
            GroundedClaim(
                text=(
                    f"Review the persisted evidence mapped to {attack_id} and validate "
                    "scope, timing, and affected assets before drawing conclusions."
                ),
                citation_ids=evidence_ids,
            )
        )
        assessment_ids.extend(evidence_ids)

    if not findings:
        preferred = [
            citation
            for citation in context.citations
            if citation.source_type in {"alert", "event", "relationship"}
        ][:3]
        if not preferred and context.citations:
            preferred = [context.citations[0]]
        for citation in preferred:
            findings.append(
                GroundedClaim(
                    text=f"ThreatLens persisted {citation.source_type} evidence: {citation.title}.",
                    citation_ids=[citation.citation_id],
                )
            )
            assessment_ids.append(citation.citation_id)
        if preferred:
            actions.append(
                GroundedClaim(
                    text=(
                        "Review the cited persisted evidence and validate scope and timing "
                        "before taking operational action."
                    ),
                    citation_ids=[preferred[0].citation_id],
                )
            )

    assessment_ids = list(dict.fromkeys(assessment_ids))[:4]
    complete_techniques = len(technique_explanations) == len(plan.attack_ids)
    confidence = "medium" if complete_techniques or not plan.attack_ids else "low"

    assessment = (
        "ThreatLens is presenting a deterministic evidence-only fallback because local "
        "model generation did not complete. The statements below are limited to persisted "
        "incident evidence and governed knowledge."
    )

    limitations = [
        (
            "Local model generation did not complete; this response was assembled "
            "deterministically from authorized ThreatLens evidence and governed knowledge."
        ),
        (
            "The fallback does not establish causation, successful compromise, credential "
            "theft, credential dumping, lateral movement, or adversary intent."
        ),
        "Analyst review is required before operational conclusions or response actions.",
    ]

    return GeneratedInvestigation(
        assessment=assessment,
        assessment_citation_ids=assessment_ids,
        key_findings=findings[:4],
        recommended_actions=actions[:3],
        technique_explanations=technique_explanations,
        limitations=limitations,
        confidence=confidence,
    )
