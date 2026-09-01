from __future__ import annotations

import os
from pathlib import Path

from core.rules.exceptions import RuleLoadError
from core.rules.models import ThreatLensRule
from core.rules.profiles import RuleProfileLoader
from core.rules.validation import RuleValidationReport, RuleValidator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULE_DIRECTORY = PROJECT_ROOT / "rules"
DEFAULT_PROFILE_PATH = PROJECT_ROOT / "config" / "rule_profiles.yml"


class RuleLoader:
    """Load a validated rule catalogue and optional environment tuning profile."""

    def __init__(
        self,
        rule_directory: Path = DEFAULT_RULE_DIRECTORY,
        profile_path: Path = DEFAULT_PROFILE_PATH,
    ) -> None:
        self.rule_directory = rule_directory
        self.profile_path = profile_path
        self.validator = RuleValidator()

    def validation_report(self) -> RuleValidationReport:
        return self.validator.validate_directory(self.rule_directory)

    def load(
        self,
        *,
        enabled_only: bool = True,
        profile: str | None = None,
    ) -> list[ThreatLensRule]:
        report = self.validation_report()
        if not report.valid:
            messages = "\n".join(f"- {issue.path}: {issue.message}" for issue in report.issues)
            raise RuleLoadError(f"Rule catalogue validation failed:\n{messages}")

        selected_profile = profile or os.getenv("THREATLENS_RULE_PROFILE", "default")
        rules = RuleProfileLoader(self.profile_path).apply(report.rules, selected_profile)
        return [rule for rule in rules if rule.enabled] if enabled_only else rules
