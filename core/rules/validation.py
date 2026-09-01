from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from core.rules.exceptions import DuplicateRuleError, RuleLoadError
from core.rules.models import ThreatLensRule

REQUIRED_FIXTURE_TYPES = {"positive", "negative", "boundary"}


@dataclass(frozen=True)
class RuleValidationIssue:
    path: str
    message: str
    severity: str = "error"


@dataclass
class RuleValidationReport:
    rules: list[ThreatLensRule] = field(default_factory=list)
    issues: list[RuleValidationIssue] = field(default_factory=list)
    source_paths: dict[str, str] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return not self.issues

    @property
    def enabled_rules(self) -> list[ThreatLensRule]:
        return [rule for rule in self.rules if rule.enabled]

    def summary(self) -> dict[str, int | bool]:
        return {
            "valid": self.valid,
            "rules": len(self.rules),
            "enabled": len(self.enabled_rules),
            "issues": len(self.issues),
        }


class RuleValidator:
    """Load YAML rules and enforce schema, lifecycle and fixture integrity."""

    def validate_file(self, path: Path) -> ThreatLensRule:
        try:
            payload: Any = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
        except (OSError, yaml.YAMLError) as error:
            raise RuleLoadError(f"Unable to read rule {path}: {error}") from error
        if not isinstance(payload, dict):
            raise RuleLoadError(f"Rule {path} must contain one YAML mapping.")
        try:
            return ThreatLensRule.model_validate(payload)
        except ValidationError as error:
            raise RuleLoadError(f"Rule validation failed for {path}:\n{error}") from error

    @staticmethod
    def _validate_fixture_manifest(rule: ThreatLensRule, fixture_path: Path) -> None:
        try:
            payload: Any = yaml.safe_load(fixture_path.read_text(encoding="utf-8-sig")) or {}
        except (OSError, yaml.YAMLError) as error:
            raise RuleLoadError(
                f"Unable to read fixture manifest for {rule.detection_name}: {error}"
            ) from error
        if not isinstance(payload, dict):
            raise RuleLoadError("Fixture manifest must contain one YAML mapping.")
        if payload.get("rule") != rule.detection_name:
            raise RuleLoadError(
                f"Fixture manifest rule mismatch: expected {rule.detection_name}, "
                f"received {payload.get('rule')!r}."
            )
        cases = payload.get("cases")
        if not isinstance(cases, list) or len(cases) < 3:
            raise RuleLoadError("Every rule requires at least three fixture cases.")

        seen_names: set[str] = set()
        seen_types: set[str] = set()
        for case in cases:
            if not isinstance(case, dict):
                raise RuleLoadError("Each fixture case must be a YAML mapping.")
            name = str(case.get("name", "")).strip()
            case_type = str(case.get("case_type", "")).strip().lower()
            filename = str(case.get("file", "")).strip()
            if not name or not filename:
                raise RuleLoadError("Fixture cases require name and file fields.")
            if name in seen_names:
                raise RuleLoadError(f"Duplicate fixture case name: {name}")
            seen_names.add(name)
            if case_type not in REQUIRED_FIXTURE_TYPES:
                raise RuleLoadError(f"Fixture case '{name}' has invalid case_type '{case_type}'.")
            seen_types.add(case_type)
            try:
                expected_alerts = int(case.get("expected_alerts"))
            except (TypeError, ValueError) as error:
                raise RuleLoadError(
                    f"Fixture case '{name}' requires integer expected_alerts."
                ) from error
            if expected_alerts < 0:
                raise RuleLoadError("expected_alerts cannot be negative.")
            fixture_file = (fixture_path.parent / filename).resolve()
            if not fixture_file.is_relative_to(fixture_path.parent.resolve()):
                raise RuleLoadError(f"Fixture file escapes its directory: {fixture_file}")
            if not fixture_file.exists():
                raise RuleLoadError(f"Fixture file does not exist: {fixture_file}")

        missing_types = REQUIRED_FIXTURE_TYPES - seen_types
        if missing_types:
            raise RuleLoadError(f"Fixture manifest is missing case types: {sorted(missing_types)}")

    def validate_directory(self, rule_directory: Path) -> RuleValidationReport:
        report = RuleValidationReport()
        paths = sorted([*rule_directory.rglob("*.yml"), *rule_directory.rglob("*.yaml")])
        paths = [path for path in paths if "fixtures" not in path.parts]
        seen_ids: dict[str, Path] = {}
        seen_names: dict[str, Path] = {}

        for path in paths:
            try:
                rule = self.validate_file(path)
                if rule.rule_id in seen_ids:
                    raise DuplicateRuleError(
                        f"Duplicate rule ID {rule.rule_id}: {seen_ids[rule.rule_id]} and {path}"
                    )
                if rule.detection_name in seen_names:
                    raise DuplicateRuleError(
                        "Duplicate detection_name "
                        f"{rule.detection_name}: {seen_names[rule.detection_name]} and {path}"
                    )
                fixture_path = (rule_directory / rule.fixtures.manifest).resolve()
                if not fixture_path.is_relative_to(rule_directory.resolve()):
                    raise RuleLoadError(f"Fixture path escapes the rule directory: {fixture_path}")
                if not fixture_path.exists():
                    raise RuleLoadError(
                        f"Fixture manifest for {rule.detection_name} does not exist: {fixture_path}"
                    )
                self._validate_fixture_manifest(rule, fixture_path)
                seen_ids[rule.rule_id] = path
                seen_names[rule.detection_name] = path
                report.rules.append(rule)
                report.source_paths[rule.rule_id] = str(path)
            except (RuleLoadError, DuplicateRuleError) as error:
                report.issues.append(RuleValidationIssue(path=str(path), message=str(error)))
        return report
