from __future__ import annotations

from dataclasses import dataclass

from rag.models import (
    GeneratedInvestigation,
    GroundedClaim,
    IncidentContext,
    RagCitation,
    RagResponseStatus,
    RetrievedChunk,
    TechniqueExplanation,
)

_KNOWLEDGE_SOURCE_TYPES = {"attack_technique", "detection_rule", "threatlens_doc"}


@dataclass(frozen=True)
class GroundingValidationResult:
    citations: list[RagCitation]
    invalid_citation_ids: list[str]
    score: float
    status: RagResponseStatus
    assessment_citation_ids: list[str]
    key_findings: list[GroundedClaim]
    recommended_actions: list[GroundedClaim]
    technique_explanations: list[TechniqueExplanation]


def build_citation_catalog(
    incident: IncidentContext,
    knowledge: list[RetrievedChunk],
) -> dict[str, RagCitation]:
    catalog: dict[str, RagCitation] = {
        item.citation_id: RagCitation(
            citation_id=item.citation_id,
            source_type=item.source_type,
            title=item.title,
            snippet=item.snippet,
            source_reference=item.source_reference,
        )
        for item in incident.citations
    }
    for item in knowledge:
        citation_id = f"KB:{item.chunk.chunk_id}"
        catalog[citation_id] = RagCitation(
            citation_id=citation_id,
            source_type=item.chunk.source_kind,
            title=item.chunk.title,
            snippet=item.chunk.text[:900],
            source_reference=item.chunk.source_reference,
            relevance=item.relevance,
        )
    return catalog


def build_technique_knowledge_bindings(
    knowledge: list[RetrievedChunk],
) -> dict[str, set[str]]:
    """Bind governed KB chunks to ATT&CK IDs they explicitly describe/map to.

    Generic governed ThreatLens documents intentionally do not receive a technique
    binding. A technique explanation therefore has to cite either the exact ATT&CK
    technique record or a governed detection rule explicitly mapped to that ID.
    """

    bindings: dict[str, set[str]] = {}
    for item in knowledge:
        metadata = item.chunk.metadata or {}
        attack_ids: list[str] = []
        if item.chunk.source_kind == "attack_technique":
            value = str(metadata.get("attack_id") or "").upper().strip()
            if value:
                attack_ids.append(value)
        elif item.chunk.source_kind == "detection_rule":
            attack_ids.extend(
                str(value).upper().strip()
                for value in metadata.get("attack_ids") or []
                if str(value).strip()
            )
        citation_id = f"KB:{item.chunk.chunk_id}"
        for attack_id in attack_ids:
            bindings.setdefault(attack_id, set()).add(citation_id)
    return bindings


def _valid_ids(ids: list[str], catalog: dict[str, RagCitation]) -> list[str]:
    return [citation_id for citation_id in dict.fromkeys(ids) if citation_id in catalog]


def _valid_plane_ids(
    ids: list[str],
    catalog: dict[str, RagCitation],
    *,
    knowledge_plane: bool,
) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    for citation_id in dict.fromkeys(ids):
        citation = catalog.get(citation_id)
        is_knowledge = bool(
            citation_id.startswith("KB:")
            or (citation and citation.source_type in _KNOWLEDGE_SOURCE_TYPES)
        )
        if citation is None or is_knowledge != knowledge_plane:
            invalid.append(citation_id)
        else:
            valid.append(citation_id)
    return valid, invalid


def _sanitize_claims(
    claims: list[GroundedClaim],
    catalog: dict[str, RagCitation],
) -> list[GroundedClaim]:
    return [
        GroundedClaim(
            text=claim.text,
            citation_ids=_valid_ids(claim.citation_ids, catalog),
        )
        for claim in claims
    ]


def _technique_quality(
    explanation: TechniqueExplanation,
    catalog: dict[str, RagCitation],
) -> tuple[int, int, int, int, int]:
    exact_attack = sum(
        1
        for citation_id in explanation.knowledge_citation_ids
        if catalog.get(citation_id) and catalog[citation_id].source_type == "attack_technique"
    )
    rule_count = sum(
        1
        for citation_id in explanation.knowledge_citation_ids
        if catalog.get(citation_id) and catalog[citation_id].source_type == "detection_rule"
    )
    return (
        int(bool(explanation.evidence_citation_ids)),
        int(bool(explanation.knowledge_citation_ids)),
        exact_attack,
        rule_count,
        len(explanation.evidence_citation_ids) + len(explanation.knowledge_citation_ids),
    )


def _sanitize_techniques(
    generated: GeneratedInvestigation,
    catalog: dict[str, RagCitation],
    *,
    technique_knowledge_bindings: dict[str, set[str]] | None = None,
    restrict_to_attack_ids: list[str] | None = None,
) -> tuple[list[TechniqueExplanation], list[str]]:
    candidates: list[TechniqueExplanation] = []
    invalid: list[str] = []
    allowed_attack_ids = (
        {value.upper() for value in restrict_to_attack_ids}
        if restrict_to_attack_ids is not None
        else None
    )

    for explanation in generated.technique_explanations:
        technique_id = explanation.technique_id.upper()
        if allowed_attack_ids is not None and technique_id not in allowed_attack_ids:
            continue

        evidence_ids, invalid_evidence = _valid_plane_ids(
            explanation.evidence_citation_ids,
            catalog,
            knowledge_plane=False,
        )
        knowledge_ids, invalid_knowledge = _valid_plane_ids(
            explanation.knowledge_citation_ids,
            catalog,
            knowledge_plane=True,
        )

        # Stronger than ordinary citation-plane validation: technique-specific
        # knowledge must explicitly describe/map to the same ATT&CK ID.
        if technique_knowledge_bindings is not None:
            permitted = technique_knowledge_bindings.get(technique_id, set())
            mismatched = [cid for cid in knowledge_ids if cid not in permitted]
            invalid_knowledge.extend(mismatched)
            knowledge_ids = [cid for cid in knowledge_ids if cid in permitted]

        invalid.extend(invalid_evidence)
        invalid.extend(invalid_knowledge)
        candidates.append(
            TechniqueExplanation(
                technique_id=technique_id,
                technique_name=explanation.technique_name,
                observed_evidence=explanation.observed_evidence,
                evidence_citation_ids=evidence_ids,
                governed_explanation=explanation.governed_explanation,
                knowledge_citation_ids=knowledge_ids,
                analyst_inference=explanation.analyst_inference,
            )
        )

    # Deterministically collapse duplicate model objects. Keep the entry with the
    # strongest validated planes, preferring an exact ATT&CK citation over a rule.
    best_by_id: dict[str, TechniqueExplanation] = {}
    first_seen: list[str] = []
    for explanation in candidates:
        technique_id = explanation.technique_id
        if technique_id not in best_by_id:
            best_by_id[technique_id] = explanation
            first_seen.append(technique_id)
            continue
        if _technique_quality(explanation, catalog) > _technique_quality(
            best_by_id[technique_id], catalog
        ):
            best_by_id[technique_id] = explanation

    if restrict_to_attack_ids is not None:
        order = [
            attack_id.upper()
            for attack_id in restrict_to_attack_ids
            if attack_id.upper() in best_by_id
        ]
    else:
        order = first_seen
    output = [best_by_id[attack_id] for attack_id in order]
    return output, list(dict.fromkeys(invalid))


def validate_grounding_detailed(
    generated: GeneratedInvestigation,
    catalog: dict[str, RagCitation],
    *,
    technique_knowledge_bindings: dict[str, set[str]] | None = None,
    restrict_to_attack_ids: list[str] | None = None,
) -> GroundingValidationResult:
    assessment_ids = _valid_ids(generated.assessment_citation_ids, catalog)
    findings = _sanitize_claims(generated.key_findings, catalog)
    actions = _sanitize_claims(generated.recommended_actions, catalog)
    techniques, technique_invalid = _sanitize_techniques(
        generated,
        catalog,
        technique_knowledge_bindings=technique_knowledge_bindings,
        restrict_to_attack_ids=restrict_to_attack_ids,
    )

    requested = list(
        dict.fromkeys(
            [
                *generated.assessment_citation_ids,
                *(cid for claim in generated.key_findings for cid in claim.citation_ids),
                *(cid for claim in generated.recommended_actions for cid in claim.citation_ids),
                *(
                    cid
                    for explanation in generated.technique_explanations
                    for cid in explanation.evidence_citation_ids
                ),
                *(
                    cid
                    for explanation in generated.technique_explanations
                    for cid in explanation.knowledge_citation_ids
                ),
            ]
        )
    )
    invalid = [citation_id for citation_id in requested if citation_id not in catalog]
    invalid.extend(technique_invalid)
    invalid = list(dict.fromkeys(invalid))

    # Only surface citations that survived both ordinary authorization and any
    # technique-specific binding checks. Citations referenced exclusively by
    # dropped duplicate/unrequested technique objects are also omitted.
    final_used_ids = list(assessment_ids)
    for claim in [*findings, *actions]:
        final_used_ids.extend(claim.citation_ids)
    for explanation in techniques:
        final_used_ids.extend(explanation.evidence_citation_ids)
        final_used_ids.extend(explanation.knowledge_citation_ids)
    final_used_ids = list(dict.fromkeys(final_used_ids))
    citations = [
        catalog[citation_id]
        for citation_id in final_used_ids
        if citation_id in catalog and citation_id not in invalid
    ]

    units = [bool(assessment_ids)]
    units.extend(bool(claim.citation_ids) for claim in findings)
    units.extend(bool(claim.citation_ids) for claim in actions)
    for explanation in techniques:
        units.append(bool(explanation.evidence_citation_ids))
        units.append(bool(explanation.knowledge_citation_ids))

    unit_score = sum(units) / len(units) if units else 0.0
    citation_score = (
        len(
            [
                citation_id
                for citation_id in requested
                if citation_id in catalog and citation_id not in invalid
            ]
        )
        / len(requested)
        if requested
        else 0.0
    )
    score = unit_score * citation_score

    if not any(units):
        status = RagResponseStatus.INSUFFICIENT_EVIDENCE
    elif score < 1.0 or invalid or generated.confidence == "low":
        status = RagResponseStatus.PARTIALLY_SUPPORTED
    else:
        status = RagResponseStatus.ANSWERED

    return GroundingValidationResult(
        citations=citations,
        invalid_citation_ids=invalid,
        score=score,
        status=status,
        assessment_citation_ids=assessment_ids,
        key_findings=findings,
        recommended_actions=actions,
        technique_explanations=techniques,
    )


def validate_grounding(
    generated: GeneratedInvestigation,
    catalog: dict[str, RagCitation],
) -> tuple[
    list[RagCitation],
    list[str],
    float,
    RagResponseStatus,
    list[str],
    list[GroundedClaim],
    list[GroundedClaim],
]:
    """Backward-compatible grounding tuple used by the existing test contract."""

    result = validate_grounding_detailed(generated, catalog)
    return (
        result.citations,
        result.invalid_citation_ids,
        result.score,
        result.status,
        result.assessment_citation_ids,
        result.key_findings,
        result.recommended_actions,
    )
