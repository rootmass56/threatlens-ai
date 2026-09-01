from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(all|any|the)?\s*(previous|prior|system)\s+instructions?\b", re.I),
    re.compile(r"\b(system|developer)\s+prompt\b", re.I),
    re.compile(r"\breveal\s+(credentials?|passwords?|secrets?|tokens?)\b", re.I),
    re.compile(r"\bexfiltrat(e|ion)\b", re.I),
    re.compile(r"\bdisable\s+(security|guardrails?|authorization)\b", re.I),
)
_ATTRIBUTION = re.compile(
    r"\b(who\s+(is|was)\s+(the\s+)?attacker|attribute\s+(this|the)\s+attack|"
    r"which\s+(apt|threat\s+actor|group)|attacker\s+identity)\b",
    re.I,
)


def normalize_question(question: str, *, max_chars: int) -> str:
    cleaned = " ".join(_CONTROL.sub(" ", question).split())
    if not cleaned:
        raise ValueError("Investigation question cannot be empty.")
    if len(cleaned) > max_chars:
        raise ValueError(f"Investigation question exceeds {max_chars} characters.")
    return cleaned


def contains_instruction_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in _INJECTION_PATTERNS)


def requires_attribution_evidence(question: str) -> bool:
    return bool(_ATTRIBUTION.search(question))


def incident_contains_attribution_evidence(details: dict) -> bool:
    allowed_types = {
        "attribution",
        "threat_intelligence",
        "threat_actor_intelligence",
    }
    markers = ("threat actor:", "attribution:", "actor identity:", "campaign:")
    for evidence in details.get("evidence") or []:
        evidence_type = str(evidence.get("evidence_type") or "").strip().lower()
        description = str(evidence.get("description") or "").lower()
        if evidence_type in allowed_types and any(marker in description for marker in markers):
            return True
    return False
