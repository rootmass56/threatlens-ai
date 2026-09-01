from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from core.rules.exceptions import RuleLoadError
from core.rules.models import ThreatLensRule

ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}


@dataclass(frozen=True)
class RuleProfileMetadata:
    name: str
    description: str
    override_count: int


class RuleProfileLoader:
    """Apply validated environment-specific rule overrides without editing source YAML."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _payload(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "profiles": {"default": {"description": "No overrides."}}}
        try:
            payload = yaml.safe_load(self.path.read_text(encoding="utf-8-sig")) or {}
        except (OSError, yaml.YAMLError) as error:
            raise RuleLoadError(f"Unable to load rule profile configuration: {error}") from error
        if not isinstance(payload, dict):
            raise RuleLoadError("Rule profile configuration must contain a YAML mapping.")
        if int(payload.get("version", 0)) != 1:
            raise RuleLoadError("Unsupported rule profile configuration version.")
        profiles = payload.get("profiles")
        if not isinstance(profiles, dict) or "default" not in profiles:
            raise RuleLoadError("Rule profiles require a default profile.")
        return payload

    def available_profiles(self) -> list[RuleProfileMetadata]:
        payload = self._payload()
        records: list[RuleProfileMetadata] = []
        for name, profile in payload["profiles"].items():
            if not isinstance(profile, dict):
                raise RuleLoadError(f"Profile {name!r} must be a YAML mapping.")
            overrides = profile.get("rules", {}) or {}
            if not isinstance(overrides, dict):
                raise RuleLoadError(f"Profile {name!r} rules must be a mapping.")
            records.append(
                RuleProfileMetadata(
                    name=str(name),
                    description=str(profile.get("description", "")),
                    override_count=len(overrides),
                )
            )
        return records

    @staticmethod
    def _apply_override(rule: ThreatLensRule, override: dict[str, Any]) -> ThreatLensRule:
        if not isinstance(override, dict):
            raise RuleLoadError(f"Override for {rule.detection_name} must be a mapping.")
        allowed = {"enabled", "severity", "confidence", "threshold", "suppression"}
        unknown = set(override) - allowed
        if unknown:
            raise RuleLoadError(
                f"Unsupported override fields for {rule.detection_name}: {sorted(unknown)}"
            )

        payload = rule.model_dump(mode="json")
        if "enabled" in override:
            if not isinstance(override["enabled"], bool):
                raise RuleLoadError("enabled override must be boolean.")
            payload["enabled"] = override["enabled"]
        if "severity" in override:
            severity = str(override["severity"])
            if severity not in ALLOWED_SEVERITIES:
                raise RuleLoadError(f"Invalid severity override: {severity}")
            payload["severity"] = severity
        if "confidence" in override:
            confidence = float(override["confidence"])
            if not 0.0 <= confidence <= 1.0:
                raise RuleLoadError("confidence override must be between 0 and 1.")
            payload["confidence"] = confidence

        if "threshold" in override:
            threshold = payload["detection"].get("threshold")
            if threshold is None:
                raise RuleLoadError(f"Rule {rule.detection_name} is not a threshold rule.")
            threshold_override = override["threshold"]
            if not isinstance(threshold_override, dict):
                raise RuleLoadError("threshold override must be a mapping.")
            unknown_threshold = set(threshold_override) - {
                "count",
                "distinct_count",
                "timeframe_minutes",
            }
            if unknown_threshold:
                raise RuleLoadError(
                    f"Unsupported threshold override fields: {sorted(unknown_threshold)}"
                )
            threshold.update(threshold_override)

        if "suppression" in override:
            suppression_override = override["suppression"]
            if not isinstance(suppression_override, dict):
                raise RuleLoadError("suppression override must be a mapping.")
            unknown_suppression = set(suppression_override) - {
                "enabled",
                "group_by",
                "timeframe_minutes",
                "max_alerts",
            }
            if unknown_suppression:
                raise RuleLoadError(
                    f"Unsupported suppression override fields: {sorted(unknown_suppression)}"
                )
            payload["tuning"]["suppression"].update(suppression_override)

        try:
            return ThreatLensRule.model_validate(payload)
        except ValidationError as error:
            raise RuleLoadError(
                f"Profile override invalidated rule {rule.detection_name}: {error}"
            ) from error

    def apply(self, rules: list[ThreatLensRule], profile_name: str) -> list[ThreatLensRule]:
        payload = self._payload()
        profiles = payload["profiles"]
        if profile_name not in profiles:
            raise RuleLoadError(
                f"Unknown rule profile {profile_name!r}. Available: {sorted(profiles)}"
            )
        profile = profiles[profile_name] or {}
        overrides = profile.get("rules", {}) or {}
        known = {rule.detection_name for rule in rules}
        unknown = set(overrides) - known
        if unknown:
            raise RuleLoadError(
                f"Profile {profile_name!r} references unknown rules: {sorted(unknown)}"
            )
        return [
            self._apply_override(rule, overrides[rule.detection_name])
            if rule.detection_name in overrides
            else rule
            for rule in rules
        ]
