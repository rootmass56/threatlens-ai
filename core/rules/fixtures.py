from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import perf_counter

import yaml

from core.connectors import build_default_connector_registry
from core.rules.engine import RuleEngine
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader


@dataclass(frozen=True)
class FixtureCaseResult:
    rule: str
    case: str
    case_type: str
    fixture_file: str
    expected_alerts: int
    actual_alerts: int
    parsed_events: int
    quarantined_records: int
    duration_ms: float
    passed: bool
    error: str | None = None


@dataclass
class FixtureExecutionReport:
    results: list[FixtureCaseResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.results)

    @property
    def passed_count(self) -> int:
        return sum(item.passed for item in self.results)

    @property
    def failed_count(self) -> int:
        return sum(not item.passed for item in self.results)

    @property
    def total_duration_ms(self) -> float:
        return round(sum(item.duration_ms for item in self.results), 3)

    def records(self) -> list[dict]:
        return [asdict(item) for item in self.results]


class RuleFixtureRunner:
    """Execute governed positive, negative and boundary fixtures for every rule."""

    def __init__(self, rule_directory: Path = DEFAULT_RULE_DIRECTORY) -> None:
        self.rule_directory = rule_directory

    def run(self) -> FixtureExecutionReport:
        report = FixtureExecutionReport()
        rules = RuleLoader(self.rule_directory).load(enabled_only=False)
        registry = build_default_connector_registry()
        for rule in rules:
            manifest_path = self.rule_directory / rule.fixtures.manifest
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig")) or {}
            for case in manifest.get("cases", []):
                fixture_path = manifest_path.parent / case["file"]
                expected = int(case["expected_alerts"])
                started = perf_counter()
                try:
                    parser_result = registry.parse(
                        fixture_path.read_bytes(),
                        filename=fixture_path.name,
                        connector_id=(rule.logsource.dataset or "linux_auth"),
                    )
                    alerts = RuleEngine([rule]).evaluate(parser_result.to_dataframe())
                    actual = len(alerts)
                    duration_ms = round((perf_counter() - started) * 1000, 3)
                    report.results.append(
                        FixtureCaseResult(
                            rule=rule.detection_name,
                            case=str(case["name"]),
                            case_type=str(case["case_type"]),
                            fixture_file=str(fixture_path),
                            expected_alerts=expected,
                            actual_alerts=actual,
                            parsed_events=len(parser_result.events),
                            quarantined_records=len(parser_result.quarantined_records),
                            duration_ms=duration_ms,
                            passed=actual == expected,
                        )
                    )
                except Exception as error:  # fixture execution captures diagnostic evidence
                    duration_ms = round((perf_counter() - started) * 1000, 3)
                    report.results.append(
                        FixtureCaseResult(
                            rule=rule.detection_name,
                            case=str(case["name"]),
                            case_type=str(case.get("case_type", "unknown")),
                            fixture_file=str(fixture_path),
                            expected_alerts=expected,
                            actual_alerts=0,
                            parsed_events=0,
                            quarantined_records=0,
                            duration_ms=duration_ms,
                            passed=False,
                            error=str(error),
                        )
                    )
        return report
