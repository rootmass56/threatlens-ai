from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.models import RuleStatus, ThreatLensRule


@dataclass(frozen=True)
class RuleQualityRecord:
    rule_id: str
    detection_name: str
    title: str
    status: str
    owner: str
    reviewers: int
    version: int
    modified: str
    last_reviewed: str
    next_review_due: str
    review_state: str
    fixture_count: int
    attack_mapping_count: int
    false_positive_count: int
    allowlist_count: int
    suppression_enabled: bool
    lifecycle_complete: bool
    fixture_complete: bool
    governance_score: int


@dataclass(frozen=True)
class CatalogQualitySummary:
    total_rules: int
    enabled_rules: int
    stable_rules: int
    test_rules: int
    deprecated_rules: int
    fixture_cases: int
    rules_with_complete_fixtures: int
    rules_with_allowlists: int
    rules_with_suppression: int
    overdue_reviews: int
    lifecycle_completeness_percent: float
    fixture_completeness_percent: float
    governance_score_percent: float
    rules_by_dataset: dict[str, int]
    rules_by_severity: dict[str, int]
    rules_by_tactic: dict[str, int]


class RuleQualityAnalyzer:
    """Calculate evidence-backed governance and coverage metrics for the rule catalogue."""

    def __init__(self, rule_directory: Path = DEFAULT_RULE_DIRECTORY) -> None:
        self.rule_directory = rule_directory

    def _fixture_count(self, rule: ThreatLensRule) -> int:
        manifest_path = self.rule_directory / rule.fixtures.manifest
        if not manifest_path.exists():
            return 0
        payload: Any = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig")) or {}
        return len(payload.get("cases", [])) if isinstance(payload, dict) else 0

    @staticmethod
    def _review_state(rule: ThreatLensRule, today: date) -> tuple[str, date]:
        reviewed = date.fromisoformat(rule.lifecycle.last_reviewed)
        due = reviewed + timedelta(days=rule.lifecycle.review_interval_days)
        if due < today:
            return "overdue", due
        if due <= today + timedelta(days=30):
            return "due_soon", due
        return "current", due

    def records(self, *, today: date | None = None) -> list[RuleQualityRecord]:
        current_date = today or datetime.now(UTC).date()
        rules = RuleLoader(self.rule_directory).load(enabled_only=False)
        records: list[RuleQualityRecord] = []
        for rule in rules:
            fixture_count = self._fixture_count(rule)
            lifecycle_complete = bool(
                rule.lifecycle.owner
                and rule.lifecycle.reviewers
                and rule.lifecycle.last_reviewed
                and rule.lifecycle.changelog
                and rule.lifecycle.changelog[-1].version == rule.version
            )
            fixture_complete = fixture_count >= 3
            review_state, next_review_due = self._review_state(rule, current_date)
            score_components = [
                lifecycle_complete,
                fixture_complete,
                bool(rule.attack),
                bool(rule.falsepositives),
                bool(rule.response.recommendation),
                bool(rule.response.playbook),
                rule.status in {RuleStatus.STABLE, RuleStatus.TEST},
                review_state != "overdue",
            ]
            governance_score = round(sum(score_components) / len(score_components) * 100)
            records.append(
                RuleQualityRecord(
                    rule_id=rule.rule_id,
                    detection_name=rule.detection_name,
                    title=rule.title,
                    status=rule.status.value,
                    owner=rule.lifecycle.owner,
                    reviewers=len(rule.lifecycle.reviewers),
                    version=rule.version,
                    modified=rule.modified,
                    last_reviewed=rule.lifecycle.last_reviewed,
                    next_review_due=next_review_due.isoformat(),
                    review_state=review_state,
                    fixture_count=fixture_count,
                    attack_mapping_count=len(rule.attack),
                    false_positive_count=len(rule.falsepositives),
                    allowlist_count=len(rule.tuning.allowlists),
                    suppression_enabled=rule.tuning.suppression.enabled,
                    lifecycle_complete=lifecycle_complete,
                    fixture_complete=fixture_complete,
                    governance_score=governance_score,
                )
            )
        return records

    def records_as_dicts(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in self.records()]

    def summary(self) -> CatalogQualitySummary:
        rules = RuleLoader(self.rule_directory).load(enabled_only=False)
        records = self.records()
        dataset_counts = Counter(rule.logsource.dataset or "unassigned" for rule in rules)
        severity_counts = Counter(rule.severity for rule in rules)
        tactic_counts = Counter(rule.primary_attack.tactic for rule in rules)
        fixture_cases = sum(record.fixture_count for record in records)
        total = len(rules)
        lifecycle_complete = sum(record.lifecycle_complete for record in records)
        fixture_complete = sum(record.fixture_complete for record in records)
        governance_total = sum(record.governance_score for record in records)
        return CatalogQualitySummary(
            total_rules=total,
            enabled_rules=sum(rule.enabled for rule in rules),
            stable_rules=sum(rule.status == RuleStatus.STABLE for rule in rules),
            test_rules=sum(rule.status == RuleStatus.TEST for rule in rules),
            deprecated_rules=sum(rule.status == RuleStatus.DEPRECATED for rule in rules),
            fixture_cases=fixture_cases,
            rules_with_complete_fixtures=fixture_complete,
            rules_with_allowlists=sum(bool(rule.tuning.allowlists) for rule in rules),
            rules_with_suppression=sum(rule.tuning.suppression.enabled for rule in rules),
            overdue_reviews=sum(record.review_state == "overdue" for record in records),
            lifecycle_completeness_percent=(
                round(lifecycle_complete / total * 100, 2) if total else 0.0
            ),
            fixture_completeness_percent=(
                round(fixture_complete / total * 100, 2) if total else 0.0
            ),
            governance_score_percent=(round(governance_total / total, 2) if total else 0.0),
            rules_by_dataset=dict(sorted(dataset_counts.items())),
            rules_by_severity=dict(sorted(severity_counts.items())),
            rules_by_tactic=dict(sorted(tactic_counts.items())),
        )
