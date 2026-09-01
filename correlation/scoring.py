from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from correlation.entities import clean_text
from correlation.stages import progression_bonus

ENTITY_WEIGHTS = {
    "ip": 0.48,
    "hostname": 0.28,
    "username": 0.28,
    "hash": 0.42,
    "process": 0.16,
    "domain": 0.14,
    "file": 0.14,
    "url": 0.10,
}


@dataclass(frozen=True)
class RelationshipScore:
    confidence: float
    relationship_type: str
    reasons: tuple[str, ...]
    shared_entities: tuple[str, ...]
    shared_entity_count: int
    shared_source_ip: bool
    same_technique: bool
    time_delta_seconds: float | None
    cluster_eligible: bool


def score_alert_relationship(
    left: pd.Series,
    right: pd.Series,
    left_entities: set[str],
    right_entities: set[str],
    *,
    threshold: float,
    window_minutes: int,
) -> RelationshipScore:
    shared = sorted(left_entities.intersection(right_entities))
    reasons: list[str] = []
    score = 0.0
    entity_score = 0.0
    shared_source_ip = False
    for key in shared:
        entity_type = key.split(":", 1)[0]
        entity_score += ENTITY_WEIGHTS.get(entity_type, 0.08)
        if entity_type == "ip":
            shared_source_ip = True
    if shared:
        entity_score = min(entity_score, 0.58)
        score += entity_score
        reasons.append(f"shared entities ({', '.join(shared[:4])})")

    left_time = pd.to_datetime(left.get("timestamp"), errors="coerce", utc=True)
    right_time = pd.to_datetime(right.get("timestamp"), errors="coerce", utc=True)
    delta_seconds: float | None = None
    if not pd.isna(left_time) and not pd.isna(right_time):
        delta_seconds = abs((right_time - left_time).total_seconds())
        if delta_seconds <= 60:
            score += 0.18
            reasons.append("within 60 seconds")
        elif delta_seconds <= 300:
            score += 0.14
            reasons.append("within 5 minutes")
        elif delta_seconds <= 900:
            score += 0.10
            reasons.append("within 15 minutes")
        elif delta_seconds <= window_minutes * 60:
            score += 0.06
            reasons.append(f"within {window_minutes} minute window")
        else:
            return RelationshipScore(
                confidence=0.0,
                relationship_type="outside_window",
                reasons=("outside correlation window",),
                shared_entities=tuple(shared),
                shared_entity_count=len(shared),
                shared_source_ip=shared_source_ip,
                same_technique=False,
                time_delta_seconds=delta_seconds,
                cluster_eligible=False,
            )

    left_dataset = clean_text(left.get("source_dataset"))
    right_dataset = clean_text(right.get("source_dataset"))
    if left_dataset and right_dataset and left_dataset != right_dataset:
        score += 0.08
        reasons.append(f"cross-source corroboration ({left_dataset}, {right_dataset})")

    left_technique = clean_text(left.get("mitre_technique_id"))
    right_technique = clean_text(right.get("mitre_technique_id"))
    same_technique = bool(left_technique and left_technique == right_technique)
    if same_technique:
        score += 0.06
        reasons.append(f"same ATT&CK technique {left_technique}")

    bonus, progression_reason = progression_bonus(
        left.get("mitre_tactic"), right.get("mitre_tactic")
    )
    score += bonus
    if progression_reason:
        reasons.append(progression_reason)

    confidence = round(min(score, 1.0), 3)
    shared_hostname = any(key.startswith("hostname:") for key in shared)
    same_dataset_host_continuity = (
        shared_hostname
        and bool(left_dataset)
        and left_dataset == right_dataset
        and delta_seconds is not None
        and delta_seconds <= 300
    )
    unknown_dataset_host_continuity = (
        shared_hostname
        and not left_dataset
        and not right_dataset
        and delta_seconds is not None
        and delta_seconds <= 300
    )
    strong_evidence = (
        shared_source_ip
        or len(shared) >= 2
        or same_technique
        or same_dataset_host_continuity
        or unknown_dataset_host_continuity
    )
    cluster_eligible = (confidence >= threshold and strong_evidence) or (
        (same_dataset_host_continuity or unknown_dataset_host_continuity) and confidence >= 0.40
    )
    if same_technique and left_dataset != right_dataset:
        relationship_type = "cross_source_corroboration"
    elif progression_reason and shared:
        relationship_type = "entity_stage_progression"
    elif shared:
        relationship_type = "shared_entity"
    else:
        relationship_type = "temporal_context"
    return RelationshipScore(
        confidence=confidence,
        relationship_type=relationship_type,
        reasons=tuple(reasons),
        shared_entities=tuple(shared),
        shared_entity_count=len(shared),
        shared_source_ip=shared_source_ip,
        same_technique=same_technique,
        time_delta_seconds=delta_seconds,
        cluster_eligible=cluster_eligible,
    )
