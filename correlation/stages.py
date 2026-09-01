from __future__ import annotations

from typing import Any

import pandas as pd

TACTIC_ORDER = {
    "Reconnaissance": 10,
    "Resource Development": 20,
    "Initial Access": 30,
    "Execution": 40,
    "Persistence": 50,
    "Privilege Escalation": 55,
    "Defense Evasion": 60,
    "Stealth": 60,
    "Defense Impairment": 62,
    "Credential Access": 70,
    "Discovery": 80,
    "Lateral Movement": 90,
    "Collection": 100,
    "Command and Control": 110,
    "Exfiltration": 120,
    "Impact": 130,
}

TACTIC_ALIASES = {
    "command-and-control": "Command and Control",
    "credential-access": "Credential Access",
    "defense-evasion": "Defense Evasion",
    "defense-impairment": "Defense Impairment",
    "initial-access": "Initial Access",
    "lateral-movement": "Lateral Movement",
    "privilege-escalation": "Privilege Escalation",
    "resource-development": "Resource Development",
}


def normalize_tactic(value: Any) -> str:
    text = str(value or "Unknown").strip()
    if not text:
        return "Unknown"
    normalized = text.replace("_", " ").replace("-", " ").lower()
    alias = TACTIC_ALIASES.get(text.lower())
    if alias:
        return alias
    for canonical in TACTIC_ORDER:
        if canonical.lower() == normalized:
            return canonical
    return " ".join(part.capitalize() for part in normalized.split())


def tactic_order(value: Any) -> int:
    return TACTIC_ORDER.get(normalize_tactic(value), 0)


def ordered_stage_sequence(frame: pd.DataFrame) -> list[str]:
    if frame.empty:
        return []
    working = frame.copy()
    working["_timestamp"] = pd.to_datetime(working.get("timestamp"), errors="coerce", utc=True)
    working = working.sort_values("_timestamp", na_position="last")
    sequence: list[str] = []
    for value in working.get("mitre_tactic", pd.Series(dtype=object)):
        tactic = normalize_tactic(value)
        if tactic != "Unknown" and tactic not in sequence:
            sequence.append(tactic)
    return sequence


def progression_bonus(first: Any, second: Any) -> tuple[float, str | None]:
    left = tactic_order(first)
    right = tactic_order(second)
    if left <= 0 or right <= 0 or left == right:
        return 0.0, None
    if right > left:
        reason = (
            f"ordered ATT&CK progression {normalize_tactic(first)} → {normalize_tactic(second)}"
        )
        return 0.14, reason
    reason = f"reverse-order ATT&CK context {normalize_tactic(first)} → {normalize_tactic(second)}"
    return 0.03, reason
