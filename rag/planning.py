from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from rag.models import RagQueryPlan

_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_KNOWLEDGE_TERMS = (
    "mitre",
    "att&ck",
    "attack technique",
    "technique",
    "governed knowledge",
    "detection rule",
    "rule knowledge",
    "what it means",
)
_EVIDENCE_TERMS = (
    "evidence",
    "persisted",
    "observed",
    "supports",
    "supporting",
    "why",
    "incident",
    "alert",
    "event",
    "relationship",
)
_SOURCE_SEPARATION_TERMS = (
    "separately",
    "distinguish",
    "versus",
    "vs",
    "both",
    "incident evidence",
    "governed knowledge",
)
_INFERENCE_SEPARATION_TERMS = (
    "analyst inference",
    "facts from inference",
    "fact from inference",
    "fact vs inference",
    "facts vs inference",
    "fact versus inference",
    "facts versus inference",
    "observed facts from analyst inference",
)
_FACT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "malware_family": (
        re.compile(r"\bmalware\s+family\b", re.I),
        re.compile(r"\bwhat\s+malware\b", re.I),
    ),
    "sha256": (
        re.compile(r"\bsha[- ]?256\b", re.I),
        re.compile(r"\bfile\s+hash\b", re.I),
    ),
    "threat_group": (
        re.compile(r"\bthreat\s+group\b", re.I),
        re.compile(r"\bapt\s*(?:group|actor|\d+)?\b", re.I),
    ),
}


def extract_attack_ids(text: str) -> list[str]:
    """Return ATT&CK IDs in stable first-seen order."""

    found: list[str] = []
    for match in _ATTACK_ID.finditer(text or ""):
        value = match.group(0).upper()
        if value not in found:
            found.append(value)
    return found


def _mapping_attack_id(mapping: Any) -> str | None:
    if not isinstance(mapping, dict):
        return None
    raw = mapping.get("technique_id") or mapping.get("attack_id")
    if not raw:
        return None
    match = _ATTACK_ID.search(str(raw))
    return match.group(0).upper() if match else None


def alert_attack_ids(alert: dict[str, Any]) -> list[str]:
    found: list[str] = []
    primary = alert.get("mitre_technique_id")
    if primary:
        found.extend(extract_attack_ids(str(primary)))
    for mapping in alert.get("attack_mappings") or alert.get("attack_mappings_json") or []:
        attack_id = _mapping_attack_id(mapping)
        if attack_id and attack_id not in found:
            found.append(attack_id)
    return found


def incident_attack_ids(details: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for alert in details.get("alerts") or []:
        for attack_id in alert_attack_ids(alert):
            if attack_id not in found:
                found.append(attack_id)
    return found


def _incident_rule_source_ids(
    details: dict[str, Any],
    attack_ids: Iterable[str],
) -> list[str]:
    wanted = set(attack_ids)
    output: list[str] = []
    for alert in details.get("alerts") or []:
        if wanted and not wanted.intersection(alert_attack_ids(alert)):
            continue
        detection_name = str(alert.get("detection_name") or "").strip()
        if not detection_name:
            continue
        source_id = f"rule:{detection_name}"
        if source_id not in output:
            output.append(source_id)
    return output


def _question_mentions_knowledge(question: str) -> bool:
    lowered = question.casefold()
    return bool(extract_attack_ids(question)) or any(term in lowered for term in _KNOWLEDGE_TERMS)


def _question_mentions_evidence(question: str) -> bool:
    lowered = question.casefold()
    return any(term in lowered for term in _EVIDENCE_TERMS)


def _requested_fact_types(question: str) -> list[str]:
    output: list[str] = []
    for fact_type, patterns in _FACT_PATTERNS.items():
        if any(pattern.search(question) for pattern in patterns):
            output.append(fact_type)
    return output


def _event_attribute_values(details: dict[str, Any], key_fragments: tuple[str, ...]) -> list[str]:
    output: list[str] = []
    for event in details.get("events") or []:
        attributes = event.get("attributes") or {}
        if not isinstance(attributes, dict):
            continue
        for key, value in attributes.items():
            lowered_key = str(key).casefold()
            if any(fragment in lowered_key for fragment in key_fragments) and value:
                output.append(str(value))
    return output


def _fact_available(details: dict[str, Any], fact_type: str) -> bool:
    if fact_type == "sha256":
        values = _event_attribute_values(details, ("sha256", "file_hash", "hash_sha256"))
        return any(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()) for value in values)

    if fact_type == "malware_family":
        values = _event_attribute_values(
            details,
            ("malware", "threat_name", "family", "signature"),
        )
        if any(value.strip() for value in values):
            return True
        for evidence in details.get("evidence") or []:
            evidence_type = str(evidence.get("evidence_type") or "").casefold()
            description = str(evidence.get("description") or "").casefold()
            if "malware" in evidence_type and any(
                marker in description
                for marker in ("family:", "malware:", "identified as", "classified as")
            ):
                return True
        return False

    if fact_type == "threat_group":
        for evidence in details.get("evidence") or []:
            evidence_type = str(evidence.get("evidence_type") or "").casefold()
            description = str(evidence.get("description") or "").casefold()
            if evidence_type in {
                "attribution",
                "threat_intelligence",
                "threat_actor_intelligence",
            } and any(
                marker in description
                for marker in ("threat actor:", "attribution:", "actor identity:", "campaign:")
            ):
                return True
        return False

    return False


def _referenced_other_incident(
    question: str,
    *,
    current_incident_title: str,
    incidents: Iterable[dict[str, Any]],
) -> str | None:
    lowered = question.casefold()
    current = current_incident_title.strip().casefold()
    for item in incidents:
        title = str(item.get("title") or "").strip()
        if not title or title.casefold() == current:
            continue
        if title.casefold() in lowered:
            return title
    return None


def build_query_plan(
    question: str,
    *,
    details: dict[str, Any],
    incidents: Iterable[dict[str, Any]] = (),
) -> RagQueryPlan:
    explicit_attack_ids = extract_attack_ids(question)
    knowledge_requested = _question_mentions_knowledge(question)

    attack_ids = list(explicit_attack_ids)
    if knowledge_requested and not attack_ids:
        attack_ids = incident_attack_ids(details)

    current_title = str((details.get("incident") or {}).get("incident_name") or "")
    referenced_other = _referenced_other_incident(
        question,
        current_incident_title=current_title,
        incidents=incidents,
    )

    source_ids: list[str] = []
    if knowledge_requested:
        for attack_id in attack_ids:
            source_id = f"attack:{attack_id}"
            if source_id not in source_ids:
                source_ids.append(source_id)
        for source_id in _incident_rule_source_ids(details, attack_ids):
            if source_id not in source_ids:
                source_ids.append(source_id)

    requested_fact_types = _requested_fact_types(question)
    missing_fact_types = [
        fact_type for fact_type in requested_fact_types if not _fact_available(details, fact_type)
    ]

    lowered = question.casefold()
    requires_source_separation = (
        knowledge_requested
        and _question_mentions_evidence(question)
        and any(term in lowered for term in _SOURCE_SEPARATION_TERMS)
    )
    requires_inference_separation = any(term in lowered for term in _INFERENCE_SEPARATION_TERMS)

    return RagQueryPlan(
        attack_ids=attack_ids,
        exact_source_ids=source_ids,
        requires_incident_evidence=True,
        requires_governed_knowledge=knowledge_requested,
        requires_source_separation=requires_source_separation,
        requires_inference_separation=requires_inference_separation,
        referenced_incident_title=referenced_other,
        incident_mismatch=referenced_other is not None,
        requested_fact_types=requested_fact_types,
        missing_fact_types=missing_fact_types,
    )
