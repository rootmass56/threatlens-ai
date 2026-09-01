from __future__ import annotations

from dataclasses import dataclass

RISK_POLICY_VERSION = "0.4.0"


@dataclass(frozen=True)
class RiskAssessment:
    """Transparent risk score and its contributing reason codes."""

    score: int
    factors: dict[str, int]
    policy_version: str = RISK_POLICY_VERSION


SEVERITY_BASE = {
    "Low": 20,
    "Medium": 45,
    "High": 70,
    "Critical": 90,
}

LEGACY_DETECTION_BONUS = {
    "multiple_failed_logins": 10,
    "successful_login_after_failures": 20,
    "suspicious_sudo_command": 15,
    "invalid_user_enumeration": 5,
}


def assess_rule_risk(
    *,
    severity: str,
    event_count: int = 1,
    context_bonus: int = 0,
    privileged_identity: bool = False,
    successful_compromise_indicator: bool = False,
) -> RiskAssessment:
    """Calculate a deterministic risk score from validated rule metadata."""

    factors = {
        "base_severity": SEVERITY_BASE.get(severity, 30),
        "rule_context": max(0, min(int(context_bonus), 30)),
        "event_volume": min(max(int(event_count), 0) * 2, 10),
        "privileged_identity": 5 if privileged_identity else 0,
        "successful_compromise_indicator": (10 if successful_compromise_indicator else 0),
    }
    return RiskAssessment(score=min(sum(factors.values()), 100), factors=factors)


def assess_alert_risk(
    detection_name: str,
    severity: str,
    event_count: int = 1,
    *,
    privileged_identity: bool = False,
    successful_compromise_indicator: bool = False,
) -> RiskAssessment:
    """Backward-compatible helper for legacy Python detections."""

    return assess_rule_risk(
        severity=severity,
        event_count=event_count,
        context_bonus=LEGACY_DETECTION_BONUS.get(detection_name, 0),
        privileged_identity=privileged_identity,
        successful_compromise_indicator=successful_compromise_indicator,
    )


def calculate_alert_risk(detection_name: str, severity: str, event_count: int = 1) -> int:
    return assess_alert_risk(detection_name, severity, event_count).score


def risk_level(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"
