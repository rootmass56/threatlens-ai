from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FIELD_EXPRESSION_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\|[a-z_]+)?$")
ATTACK_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SUPPORTED_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "regex",
    "in",
    "exists",
    "greater_than",
    "less_than",
}


def _validate_date(value: str, field_name: str) -> str:
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must use ISO YYYY-MM-DD format.") from error
    return value


def _validate_expression_mapping(expressions: dict[str, Any]) -> dict[str, Any]:
    if not expressions:
        raise ValueError("Expression mappings cannot be empty.")
    for expression, expected in expressions.items():
        if not FIELD_EXPRESSION_PATTERN.fullmatch(expression):
            raise ValueError(f"Invalid field expression: {expression}")
        _, _, operator = expression.partition("|")
        operator = operator or "equals"
        if operator not in SUPPORTED_OPERATORS:
            raise ValueError(f"Unsupported operator '{operator}' in {expression}.")
        values = expected if isinstance(expected, list) else [expected]
        if len(values) > 100:
            raise ValueError(f"Expression {expression} exceeds the 100-value safety limit.")
        if operator == "regex":
            for pattern in values:
                if len(str(pattern)) > 512:
                    raise ValueError("Regex patterns cannot exceed 512 characters.")
                try:
                    re.compile(str(pattern))
                except re.error as error:
                    raise ValueError(
                        f"Invalid regular expression in {expression}: {error}"
                    ) from error
    return expressions


class RuleStatus(StrEnum):
    DRAFT = "draft"
    TEST = "test"
    STABLE = "stable"
    DEPRECATED = "deprecated"


class RuleKind(StrEnum):
    EVENT = "event"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"


class LogSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=64)
    service: str = Field(min_length=1, max_length=64)
    dataset: str | None = Field(default=None, max_length=128)


class AttackMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    technique: str = Field(min_length=1, max_length=255)
    tactic: str = Field(min_length=1, max_length=128)
    role: Literal["primary", "secondary"] = "secondary"
    confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    justification: str = Field(min_length=5, max_length=2048)

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not ATTACK_TECHNIQUE_PATTERN.fullmatch(normalized):
            raise ValueError("ATT&CK technique IDs must use T#### or T####.### format.")
        return normalized


class RuleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    recommendation: str = Field(min_length=5, max_length=4096)
    playbook: str | None = Field(default=None, max_length=255)


class RuleRiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    context_bonus: int = Field(default=0, ge=0, le=30)
    privileged_identity: bool = False
    successful_compromise_indicator: bool = False


class ThresholdConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    selection: str
    count: int = Field(ge=1)
    distinct_field: str | None = None
    distinct_count: int | None = Field(default=None, ge=1)
    group_by: list[str] = Field(default_factory=list)
    timeframe_minutes: int = Field(default=15, ge=1, le=10080)

    @model_validator(mode="after")
    def validate_distinct_pair(self) -> ThresholdConfig:
        if (self.distinct_field is None) != (self.distinct_count is None):
            raise ValueError("distinct_field and distinct_count must be configured together.")
        return self


class SequenceStage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    selection: str
    min_count: int = Field(default=1, ge=1)
    include_all_matching: bool = True


class SequenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stages: list[SequenceStage] = Field(min_length=2)
    group_by: list[str] = Field(default_factory=list)
    timeframe_minutes: int = Field(default=15, ge=1, le=10080)


class DetectionDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    selections: dict[str, dict[str, Any]] = Field(min_length=1)
    condition: str = Field(min_length=1, max_length=512)
    threshold: ThresholdConfig | None = None
    sequence: SequenceConfig | None = None

    @field_validator("selections")
    @classmethod
    def validate_selection_expressions(
        cls,
        selections: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        for selection_name, expressions in selections.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", selection_name):
                raise ValueError(f"Invalid selection name: {selection_name}")
            _validate_expression_mapping(expressions)
        return selections


class RuleFixtureReferences(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: str = Field(min_length=1, max_length=1024)


class RuleChangelogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    date: str
    summary: str = Field(min_length=5, max_length=1024)

    @field_validator("date")
    @classmethod
    def validate_entry_date(cls, value: str) -> str:
        return _validate_date(value, "changelog date")


class RuleDeprecation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str = Field(min_length=5, max_length=1024)
    replacement_rule_id: UUID | None = None


class RuleLifecycle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: str = Field(min_length=2, max_length=255)
    reviewers: list[str] = Field(min_length=1)
    last_reviewed: str
    review_interval_days: int = Field(default=90, ge=7, le=730)
    changelog: list[RuleChangelogEntry] = Field(min_length=1)
    deprecation: RuleDeprecation | None = None

    @field_validator("last_reviewed")
    @classmethod
    def validate_last_reviewed(cls, value: str) -> str:
        return _validate_date(value, "last_reviewed")


class RuleAllowlist(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=3, max_length=128)
    reason: str = Field(min_length=5, max_length=1024)
    enabled: bool = True
    expressions: dict[str, Any]

    @field_validator("expressions")
    @classmethod
    def validate_expressions(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_expression_mapping(value)


class RuleSuppression(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    group_by: list[str] = Field(default_factory=list)
    timeframe_minutes: int = Field(default=30, ge=1, le=10080)
    max_alerts: int = Field(default=1, ge=1, le=100)

    @model_validator(mode="after")
    def validate_enabled_configuration(self) -> RuleSuppression:
        if self.enabled and not self.group_by:
            raise ValueError("Enabled suppression requires at least one group_by field.")
        return self


class RuleTuning(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowlists: list[RuleAllowlist] = Field(default_factory=list)
    suppression: RuleSuppression = Field(default_factory=RuleSuppression)
    parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)


class ThreatLensRule(BaseModel):
    """Validated Sigma-inspired ThreatLens detection rule with lifecycle controls."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=3, max_length=255)
    id: UUID
    detection_name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    version: int = Field(ge=1)
    status: RuleStatus
    enabled: bool = True
    kind: RuleKind
    description: str = Field(min_length=10, max_length=4096)
    author: str = Field(min_length=2, max_length=255)
    date: str
    modified: str
    tags: list[str] = Field(default_factory=list)
    logsource: LogSource
    detection: DetectionDefinition
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    message_template: str = Field(min_length=5, max_length=2048)
    attack: list[AttackMapping] = Field(min_length=1)
    falsepositives: list[str] = Field(default_factory=list)
    response: RuleResponse
    risk: RuleRiskConfig = Field(default_factory=RuleRiskConfig)
    lifecycle: RuleLifecycle
    tuning: RuleTuning = Field(default_factory=RuleTuning)
    fixtures: RuleFixtureReferences

    @field_validator("date", "modified")
    @classmethod
    def validate_rule_dates(cls, value: str, info) -> str:
        return _validate_date(value, info.field_name)

    @model_validator(mode="after")
    def validate_rule_consistency(self) -> ThreatLensRule:
        if self.kind == RuleKind.EVENT:
            if self.detection.threshold or self.detection.sequence:
                raise ValueError("Event rules cannot define threshold or sequence configuration.")
        elif self.kind == RuleKind.THRESHOLD:
            if not self.detection.threshold or self.detection.sequence:
                raise ValueError("Threshold rules require only a threshold configuration.")
            if self.detection.threshold.selection not in self.detection.selections:
                raise ValueError("Threshold configuration references an unknown selection.")
        elif self.kind == RuleKind.SEQUENCE:
            if not self.detection.sequence or self.detection.threshold:
                raise ValueError("Sequence rules require only a sequence configuration.")
            unknown = {
                stage.selection
                for stage in self.detection.sequence.stages
                if stage.selection not in self.detection.selections
            }
            if unknown:
                raise ValueError(f"Sequence references unknown selections: {sorted(unknown)}")

        primary_count = sum(item.role == "primary" for item in self.attack)
        if primary_count != 1:
            raise ValueError("Every rule requires exactly one primary ATT&CK mapping.")

        condition_names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", self.detection.condition))
        reserved = {"and", "or", "not", "all", "any", "of", "them"}
        unknown_names = condition_names - set(self.detection.selections) - reserved
        if unknown_names:
            raise ValueError(f"Condition references unknown selections: {sorted(unknown_names)}")

        if date.fromisoformat(self.modified) < date.fromisoformat(self.date):
            raise ValueError("modified cannot be earlier than date.")
        if date.fromisoformat(self.lifecycle.last_reviewed) < date.fromisoformat(self.date):
            raise ValueError("last_reviewed cannot be earlier than the rule creation date.")

        versions = {entry.version for entry in self.lifecycle.changelog}
        if self.version not in versions:
            raise ValueError("The changelog must include the current rule version.")
        if len(versions) != len(self.lifecycle.changelog):
            raise ValueError("Changelog versions must be unique.")

        if self.status == RuleStatus.DEPRECATED and self.lifecycle.deprecation is None:
            raise ValueError("Deprecated rules require deprecation metadata.")
        if self.status != RuleStatus.DEPRECATED and self.lifecycle.deprecation is not None:
            raise ValueError("Only deprecated rules may define deprecation metadata.")
        return self

    @property
    def rule_id(self) -> str:
        return str(self.id)

    @property
    def primary_attack(self) -> AttackMapping:
        return next(item for item in self.attack if item.role == "primary")
