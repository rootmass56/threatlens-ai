from __future__ import annotations

import re

from rag.models import GeneratedInvestigation, GroundedClaim, TechniqueExplanation


def _clean_space(text: str) -> str:
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    return text.strip()


def enforce_conservative_incident_language(text: str) -> str:
    """Downgrade common high-risk SOC overclaims without altering governed source text."""

    replacements = (
        (
            re.compile(
                r"\bindicating\s+(?:potential\s+)?credential theft(?:\s+and\s+lateral movement)?\b",
                re.I,
            ),
            "requiring further validation of credential-access activity",
        ),
        (
            re.compile(r"\bindicating\s+(?:potential\s+)?credential[- ]dumping activity\b", re.I),
            "requiring validation for possible credential-dumping activity",
        ),
        (
            re.compile(
                r"\bis a direct credential[- ]dumping indicator(?: requiring validation)?\b",
                re.I,
            ),
            "is a credential-access signal that requires validation",
        ),
        (
            re.compile(r"\bindicating\s+(?:a\s+)?potential escalation path\b", re.I),
            "supporting an observed ATT&CK stage relationship",
        ),
        (
            re.compile(r"\bwhich could lead to unauthorized system control\b", re.I),
            "which warrants further investigation",
        ),
    )
    output = text
    for pattern, replacement in replacements:
        output = pattern.sub(replacement, output)
    return _clean_space(output)


def harden_generated_investigation(
    generated: GeneratedInvestigation,
) -> GeneratedInvestigation:
    """Apply deterministic presentation safety to incident-facing model prose."""

    return GeneratedInvestigation(
        assessment=enforce_conservative_incident_language(generated.assessment),
        assessment_citation_ids=generated.assessment_citation_ids,
        key_findings=[
            GroundedClaim(
                text=enforce_conservative_incident_language(item.text),
                citation_ids=item.citation_ids,
            )
            for item in generated.key_findings
        ],
        recommended_actions=generated.recommended_actions,
        technique_explanations=[
            TechniqueExplanation(
                technique_id=item.technique_id,
                technique_name=item.technique_name,
                observed_evidence=enforce_conservative_incident_language(item.observed_evidence),
                evidence_citation_ids=item.evidence_citation_ids,
                governed_explanation=item.governed_explanation,
                knowledge_citation_ids=item.knowledge_citation_ids,
                analyst_inference=(
                    enforce_conservative_incident_language(item.analyst_inference)
                    if item.analyst_inference
                    else None
                ),
            )
            for item in generated.technique_explanations
        ],
        limitations=generated.limitations,
        confidence=generated.confidence,
    )


def repair_missing_assessment_provenance(
    generated: GeneratedInvestigation,
    grounded_findings: list[GroundedClaim],
) -> GeneratedInvestigation:
    """Replace an uncited assessment with a deterministic cited summary.

    The replacement is built only from findings that already survived grounding
    validation. Citation IDs are copied from those findings; no citation is
    invented or inferred from model prose. If there is no grounded finding to
    summarize, the original assessment is preserved and remains unsupported.
    """

    if generated.assessment_citation_ids:
        return generated

    supported = [item for item in grounded_findings if item.citation_ids]
    if not supported:
        return generated

    selected = supported[:2]
    assessment = " ".join(item.text.strip() for item in selected if item.text.strip()).strip()
    if not assessment:
        return generated

    citation_ids: list[str] = []
    for item in selected:
        for citation_id in item.citation_ids:
            if citation_id not in citation_ids:
                citation_ids.append(citation_id)
            if len(citation_ids) >= 4:
                break
        if len(citation_ids) >= 4:
            break

    if not citation_ids:
        return generated

    return GeneratedInvestigation(
        assessment=assessment,
        assessment_citation_ids=citation_ids,
        key_findings=generated.key_findings,
        recommended_actions=generated.recommended_actions,
        technique_explanations=generated.technique_explanations,
        limitations=generated.limitations,
        confidence=generated.confidence,
    )
