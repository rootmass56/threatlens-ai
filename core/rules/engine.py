from __future__ import annotations

import ast
import numbers
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from core.risk_scoring import assess_rule_risk
from core.rules.exceptions import RuleEvaluationError
from core.rules.models import RuleKind, RuleTuning, ThreatLensRule

ALERT_COLUMNS = [
    "alert_id",
    "rule_id",
    "rule_title",
    "rule_status",
    "rule_owner",
    "rule_last_reviewed",
    "event_id",
    "supporting_event_ids",
    "timestamp",
    "source_ip",
    "username",
    "hostname",
    "detection_name",
    "detection_version",
    "severity",
    "confidence",
    "description",
    "mitre_tactic",
    "mitre_technique",
    "mitre_technique_id",
    "attack_mappings",
    "recommendation",
    "playbook",
    "risk_score",
    "risk_factors",
    "risk_policy_version",
    "event_count",
    "allowlist_count",
    "suppression_policy",
]


@dataclass(frozen=True)
class _RuleMatch:
    primary: pd.Series
    supporting: pd.DataFrame
    context: dict[str, Any]


@dataclass(frozen=True)
class RuleEvaluationMetrics:
    evaluated_rules: int
    input_events: int
    generated_alerts: int
    allowlisted_events: int
    suppressed_alerts: int
    matches_by_rule: dict[str, int] = field(default_factory=dict)
    allowlisted_by_rule: dict[str, int] = field(default_factory=dict)
    suppressed_by_rule: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleEvaluationResult:
    alerts: pd.DataFrame
    metrics: RuleEvaluationMetrics


class _SafeTemplateDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "unknown"


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and pd.isna(value):
        return True
    if isinstance(value, str) and value.strip().lower() in {"", "nan", "none", "nat", "null"}:
        return True
    return False


def _series_value(row: pd.Series, field: str) -> Any:
    if field in row:
        return row.get(field)
    attributes = row.get("attributes") or {}
    if isinstance(attributes, dict):
        return attributes.get(field)
    return None


def _as_values(expected: Any) -> list[Any]:
    return expected if isinstance(expected, list) else [expected]


def _match_expression(actual: Any, operator: str, expected: Any) -> bool:
    values = _as_values(expected)
    actual_missing = _is_missing(actual)
    if operator == "exists":
        desired = bool(values[0])
        return (not actual_missing) is desired
    if actual_missing:
        return operator in {"not_equals", "not_contains"}

    actual_text = str(actual)
    actual_lower = actual_text.lower()
    if operator == "equals":
        return any(
            (
                isinstance(actual, numbers.Number)
                and not isinstance(actual, bool)
                and isinstance(value, numbers.Number)
                and not isinstance(value, bool)
                and float(actual) == float(value)
            )
            or actual_lower == str(value).lower()
            for value in values
        )
    if operator == "not_equals":
        return all(
            not (
                isinstance(actual, numbers.Number)
                and not isinstance(actual, bool)
                and isinstance(value, numbers.Number)
                and not isinstance(value, bool)
                and float(actual) == float(value)
            )
            and actual_lower != str(value).lower()
            for value in values
        )
    if operator == "contains":
        return any(str(value).lower() in actual_lower for value in values)
    if operator == "not_contains":
        return all(str(value).lower() not in actual_lower for value in values)
    if operator == "starts_with":
        return any(actual_lower.startswith(str(value).lower()) for value in values)
    if operator == "ends_with":
        return any(actual_lower.endswith(str(value).lower()) for value in values)
    if operator == "regex":
        return any(re.search(str(value), actual_text, re.IGNORECASE) for value in values)
    if operator == "in":
        return any(actual_lower == str(value).lower() for value in values)
    if operator in {"greater_than", "less_than"}:
        try:
            actual_number = float(actual)
            expected_number = float(values[0])
        except (TypeError, ValueError) as error:
            raise RuleEvaluationError(
                f"Numeric operator '{operator}' received non-numeric values."
            ) from error
        return (
            actual_number > expected_number
            if operator == "greater_than"
            else actual_number < expected_number
        )
    raise RuleEvaluationError(f"Unsupported operator at runtime: {operator}")


def _selection_mask(frame: pd.DataFrame, expressions: dict[str, Any]) -> pd.Series:
    mask = pd.Series(True, index=frame.index, dtype=bool)
    for expression, expected in expressions.items():
        field, _, operator = expression.partition("|")
        operator = operator or "equals"
        field_mask = frame.apply(
            lambda row, field=field, operator=operator, expected=expected: _match_expression(
                _series_value(row, field), operator, expected
            ),
            axis=1,
        )
        mask &= field_mask
    return mask


def _evaluate_boolean_ast(node: ast.AST, values: dict[str, bool]) -> bool:
    if isinstance(node, ast.Expression):
        return _evaluate_boolean_ast(node.body, values)
    if isinstance(node, ast.Name):
        if node.id not in values:
            raise RuleEvaluationError(f"Unknown selection in condition: {node.id}")
        return values[node.id]
    if isinstance(node, ast.BoolOp):
        evaluated = [_evaluate_boolean_ast(item, values) for item in node.values]
        if isinstance(node.op, ast.And):
            return all(evaluated)
        if isinstance(node.op, ast.Or):
            return any(evaluated)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _evaluate_boolean_ast(node.operand, values)
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    raise RuleEvaluationError("Only selection names with and/or/not are allowed in conditions.")


def _condition_mask(
    frame: pd.DataFrame,
    selections: dict[str, pd.Series],
    condition: str,
) -> pd.Series:
    normalized = condition.strip()
    if normalized == "all of them":
        result = pd.Series(True, index=frame.index, dtype=bool)
        for mask in selections.values():
            result &= mask
        return result
    if normalized in {"any of them", "1 of them"}:
        result = pd.Series(False, index=frame.index, dtype=bool)
        for mask in selections.values():
            result |= mask
        return result
    wildcard = re.fullmatch(r"(?:any|1) of (?P<prefix>[A-Za-z_][A-Za-z0-9_]*)\*", normalized)
    if wildcard:
        matching = [
            mask for name, mask in selections.items() if name.startswith(wildcard.group("prefix"))
        ]
        if not matching:
            raise RuleEvaluationError("Wildcard condition did not match any selections.")
        result = pd.Series(False, index=frame.index, dtype=bool)
        for mask in matching:
            result |= mask
        return result

    try:
        tree = ast.parse(normalized, mode="eval")
    except SyntaxError as error:
        raise RuleEvaluationError(f"Invalid condition syntax: {condition}") from error
    return frame.apply(
        lambda row: _evaluate_boolean_ast(
            tree,
            {name: bool(mask.loc[row.name]) for name, mask in selections.items()},
        ),
        axis=1,
    )


def _group_iterator(frame: pd.DataFrame, group_by: list[str]):
    if not group_by:
        yield (), frame
        return

    available = [field for field in group_by if field in frame.columns]
    if len(available) != len(group_by):
        missing = sorted(set(group_by) - set(available))
        raise RuleEvaluationError(f"Rule groups by unavailable fields: {missing}")

    grouper: str | list[str] = available[0] if len(available) == 1 else available
    yield from frame.groupby(grouper, dropna=False)


def _build_context(primary: pd.Series, supporting: pd.DataFrame) -> dict[str, Any]:
    usernames = sorted(
        {
            str(value).strip()
            for value in supporting.get("username", pd.Series(dtype=str)).dropna()
            if str(value).strip()
        }
    )
    return {
        "event_count": len(supporting),
        "source_ip": "" if _is_missing(primary.get("source_ip")) else primary.get("source_ip"),
        "destination_ip": (
            "" if _is_missing(primary.get("destination_ip")) else primary.get("destination_ip")
        ),
        "destination_port": (
            "" if _is_missing(primary.get("destination_port")) else primary.get("destination_port")
        ),
        "username": ("" if _is_missing(primary.get("username")) else primary.get("username"))
        or ", ".join(usernames),
        "usernames": ", ".join(usernames),
        "hostname": "" if _is_missing(primary.get("hostname")) else primary.get("hostname"),
        "event_type": primary.get("event_type") or "unknown",
        "command_line": primary.get("command_line") or "",
        "process_name": primary.get("process_name") or "",
        "parent_process_name": primary.get("parent_process_name") or "",
        "file_path": primary.get("file_path") or "",
        "domain": primary.get("domain") or "",
        "url": primary.get("url") or "",
    }


def _threshold_matches(
    frame: pd.DataFrame,
    rule: ThreatLensRule,
    selection_masks: dict[str, pd.Series],
) -> list[_RuleMatch]:
    config = rule.detection.threshold
    if config is None:
        return []
    selected = frame[selection_masks[config.selection]].copy()
    selected["_timestamp_dt"] = pd.to_datetime(selected["timestamp"], errors="coerce", utc=True)
    selected = selected.sort_values("_timestamp_dt", na_position="last")
    matches: list[_RuleMatch] = []
    for _, group in _group_iterator(selected, config.group_by):
        group = group.reset_index(drop=True)
        cursor = 0
        while cursor < len(group):
            start = group.loc[cursor, "_timestamp_dt"]
            if pd.isna(start):
                window = group.iloc[[cursor]]
            else:
                end = start + pd.Timedelta(minutes=config.timeframe_minutes)
                window = group[(group["_timestamp_dt"] >= start) & (group["_timestamp_dt"] <= end)]
            count_ok = len(window) >= config.count
            distinct_ok = True
            if config.distinct_field and config.distinct_count:
                if config.distinct_field not in window.columns:
                    raise RuleEvaluationError(
                        f"Distinct field unavailable: {config.distinct_field}"
                    )
                distinct_ok = (
                    window[config.distinct_field].nunique(dropna=True) >= config.distinct_count
                )
            if count_ok and distinct_ok:
                supporting = window.drop(columns=["_timestamp_dt"])
                primary = supporting.iloc[0]
                matches.append(
                    _RuleMatch(
                        primary=primary,
                        supporting=supporting,
                        context=_build_context(primary, supporting),
                    )
                )
                cursor = int(window.index.max()) + 1
            else:
                cursor += 1
    return matches


def _sequence_matches(
    frame: pd.DataFrame,
    rule: ThreatLensRule,
    selection_masks: dict[str, pd.Series],
) -> list[_RuleMatch]:
    config = rule.detection.sequence
    if config is None:
        return []
    working = frame.copy()
    working["_timestamp_dt"] = pd.to_datetime(working["timestamp"], errors="coerce", utc=True)
    matches: list[_RuleMatch] = []
    final_stage = config.stages[-1]
    final_candidates = working[selection_masks[final_stage.selection]].copy()

    for _, final_row in final_candidates.iterrows():
        final_time = final_row["_timestamp_dt"]
        if pd.isna(final_time):
            continue
        start_time = final_time - pd.Timedelta(minutes=config.timeframe_minutes)
        candidate = working[
            (working["_timestamp_dt"] >= start_time) & (working["_timestamp_dt"] <= final_time)
        ].copy()
        if config.group_by:
            for field in config.group_by:
                candidate = candidate[candidate[field] == final_row.get(field)]
        selected_parts: list[pd.DataFrame] = []
        cursor_time = final_time
        valid = True
        for stage in reversed(config.stages[:-1]):
            stage_frame = candidate[
                selection_masks[stage.selection].reindex(candidate.index, fill_value=False)
                & (candidate["_timestamp_dt"] <= cursor_time)
            ].sort_values("_timestamp_dt")
            if len(stage_frame) < stage.min_count:
                valid = False
                break
            chosen = (
                stage_frame if stage.include_all_matching else stage_frame.tail(stage.min_count)
            )
            selected_parts.append(chosen)
            cursor_time = chosen["_timestamp_dt"].min()
        if not valid:
            continue
        final_frame = pd.DataFrame([final_row])
        selected_parts.reverse()
        supporting = pd.concat([*selected_parts, final_frame]).drop_duplicates(subset=["event_id"])
        supporting = supporting.sort_values("_timestamp_dt").drop(columns=["_timestamp_dt"])
        primary = final_row.drop(labels=["_timestamp_dt"])
        matches.append(
            _RuleMatch(
                primary=primary,
                supporting=supporting,
                context=_build_context(primary, supporting),
            )
        )
    return matches


def _apply_allowlists(frame: pd.DataFrame, tuning: RuleTuning) -> tuple[pd.DataFrame, int]:
    if frame.empty or not tuning.allowlists:
        return frame, 0
    allowlisted = pd.Series(False, index=frame.index, dtype=bool)
    for item in tuning.allowlists:
        if item.enabled:
            allowlisted |= _selection_mask(frame, item.expressions)
    count = int(allowlisted.sum())
    return frame[~allowlisted].copy(), count


def _suppression_key(match: _RuleMatch, rule: ThreatLensRule) -> tuple[str, ...]:
    fields = rule.tuning.suppression.group_by
    values = []
    for field_name in fields:
        value = _series_value(match.primary, field_name)
        values.append("<missing>" if _is_missing(value) else str(value).strip().lower())
    return (rule.rule_id, *values)


def _match_timestamp(match: _RuleMatch) -> pd.Timestamp:
    parsed = pd.to_datetime(match.primary.get("timestamp"), errors="coerce", utc=True)
    return pd.Timestamp.min.tz_localize("UTC") if pd.isna(parsed) else parsed


class RuleEngine:
    """Evaluate validated external rules with allowlist and suppression controls."""

    def __init__(self, rules: list[ThreatLensRule]) -> None:
        self.rules = [rule for rule in rules if rule.enabled]

    @staticmethod
    def _source_frame(frame: pd.DataFrame, rule: ThreatLensRule) -> pd.DataFrame:
        filtered = frame
        filters = {
            "source_category": rule.logsource.category,
            "source_product": rule.logsource.product,
            "source_service": rule.logsource.service,
        }
        if rule.logsource.dataset:
            filters["source_dataset"] = rule.logsource.dataset
        for field_name, expected in filters.items():
            if str(expected).lower() in {"*", "any"}:
                continue
            if field_name not in filtered.columns:
                return filtered.iloc[0:0]
            filtered = filtered[filtered[field_name].astype(str).str.lower() == expected.lower()]
        return filtered

    def evaluate_detailed(self, events_df: pd.DataFrame) -> RuleEvaluationResult:
        if events_df.empty:
            metrics = RuleEvaluationMetrics(
                evaluated_rules=len(self.rules),
                input_events=0,
                generated_alerts=0,
                allowlisted_events=0,
                suppressed_alerts=0,
            )
            return RuleEvaluationResult(pd.DataFrame(columns=ALERT_COLUMNS), metrics)

        alerts: list[dict[str, Any]] = []
        next_alert_id = 1
        allowlisted_total = 0
        suppressed_total = 0
        matches_by_rule: dict[str, int] = defaultdict(int)
        allowlisted_by_rule: dict[str, int] = defaultdict(int)
        suppressed_by_rule: dict[str, int] = defaultdict(int)
        suppression_state: dict[tuple[str, ...], deque[pd.Timestamp]] = defaultdict(deque)

        for rule in self.rules:
            frame = self._source_frame(events_df.copy(), rule)
            frame, allowlisted_count = _apply_allowlists(frame, rule.tuning)
            allowlisted_total += allowlisted_count
            allowlisted_by_rule[rule.detection_name] += allowlisted_count
            if frame.empty:
                continue

            selection_masks = {
                name: _selection_mask(frame, expressions)
                for name, expressions in rule.detection.selections.items()
            }
            if rule.kind == RuleKind.EVENT:
                condition = _condition_mask(frame, selection_masks, rule.detection.condition)
                matches = [
                    _RuleMatch(
                        primary=row,
                        supporting=pd.DataFrame([row]),
                        context=_build_context(row, pd.DataFrame([row])),
                    )
                    for _, row in frame[condition].iterrows()
                ]
            elif rule.kind == RuleKind.THRESHOLD:
                matches = _threshold_matches(frame, rule, selection_masks)
            else:
                matches = _sequence_matches(frame, rule, selection_masks)

            matches_by_rule[rule.detection_name] += len(matches)
            for match in matches:
                suppression = rule.tuning.suppression
                if suppression.enabled:
                    key = _suppression_key(match, rule)
                    timestamp = _match_timestamp(match)
                    history = suppression_state[key]
                    start = timestamp - pd.Timedelta(minutes=suppression.timeframe_minutes)
                    while history and history[0] < start:
                        history.popleft()
                    if len(history) >= suppression.max_alerts:
                        suppressed_total += 1
                        suppressed_by_rule[rule.detection_name] += 1
                        continue
                    history.append(timestamp)

                primary_attack = rule.primary_attack
                risk = assess_rule_risk(
                    severity=rule.severity,
                    event_count=len(match.supporting),
                    context_bonus=rule.risk.context_bonus,
                    privileged_identity=rule.risk.privileged_identity,
                    successful_compromise_indicator=(rule.risk.successful_compromise_indicator),
                )
                attack_mappings = [item.model_dump(mode="json") for item in rule.attack]
                suppression_policy = (
                    {
                        "enabled": suppression.enabled,
                        "group_by": suppression.group_by,
                        "timeframe_minutes": suppression.timeframe_minutes,
                        "max_alerts": suppression.max_alerts,
                    }
                    if suppression.enabled
                    else {"enabled": False}
                )
                alerts.append(
                    {
                        "alert_id": next_alert_id,
                        "rule_id": rule.rule_id,
                        "rule_title": rule.title,
                        "rule_status": rule.status.value,
                        "rule_owner": rule.lifecycle.owner,
                        "rule_last_reviewed": rule.lifecycle.last_reviewed,
                        "event_id": int(match.primary["event_id"]),
                        "supporting_event_ids": sorted(
                            set(match.supporting["event_id"].astype(int).tolist())
                        ),
                        "timestamp": match.primary.get("timestamp", ""),
                        "source_ip": match.context["source_ip"],
                        "username": match.context["username"],
                        "hostname": match.context["hostname"],
                        "detection_name": rule.detection_name,
                        "detection_version": str(rule.version),
                        "severity": rule.severity,
                        "confidence": rule.confidence,
                        "description": rule.message_template.format_map(
                            _SafeTemplateDict(match.context)
                        ),
                        "mitre_tactic": primary_attack.tactic,
                        "mitre_technique": primary_attack.technique,
                        "mitre_technique_id": primary_attack.technique_id,
                        "attack_mappings": attack_mappings,
                        "recommendation": rule.response.recommendation,
                        "playbook": rule.response.playbook or "",
                        "risk_score": risk.score,
                        "risk_factors": risk.factors,
                        "risk_policy_version": risk.policy_version,
                        "event_count": len(match.supporting),
                        "allowlist_count": allowlisted_count,
                        "suppression_policy": suppression_policy,
                    }
                )
                next_alert_id += 1

        alerts_df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
        metrics = RuleEvaluationMetrics(
            evaluated_rules=len(self.rules),
            input_events=len(events_df),
            generated_alerts=len(alerts_df),
            allowlisted_events=allowlisted_total,
            suppressed_alerts=suppressed_total,
            matches_by_rule=dict(sorted(matches_by_rule.items())),
            allowlisted_by_rule=dict(sorted(allowlisted_by_rule.items())),
            suppressed_by_rule=dict(sorted(suppressed_by_rule.items())),
        )
        return RuleEvaluationResult(alerts=alerts_df, metrics=metrics)

    def evaluate(self, events_df: pd.DataFrame) -> pd.DataFrame:
        return self.evaluate_detailed(events_df).alerts
