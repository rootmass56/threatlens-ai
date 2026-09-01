from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from core.connectors import ConnectorRegistry, build_default_connector_registry
from core.correlation_engine import AdvancedCorrelationResult, advanced_correlate_alerts
from core.detection_engine import detect_alerts
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.validation import RuleValidationReport
from core.schema import COMMON_EVENT_COLUMNS, ParserResult
from core.timeline_builder import build_timeline


@dataclass(frozen=True)
class SourceInput:
    """One security-telemetry source submitted to a batch analysis."""

    raw_content: str | bytes
    filename: str | None = None
    connector_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisPipelineResult:
    """Complete deterministic single-source or multi-source analysis output."""

    events_df: pd.DataFrame
    alerts_df: pd.DataFrame
    incidents_df: pd.DataFrame
    timeline_df: pd.DataFrame
    parser_result: ParserResult | None = None
    parser_results: tuple[ParserResult, ...] = ()
    source_manifest: tuple[dict[str, Any], ...] = ()
    rule_validation: RuleValidationReport | None = None
    correlation_result: AdvancedCorrelationResult | None = None

    @property
    def event_count(self) -> int:
        return len(self.events_df)

    @property
    def alert_count(self) -> int:
        return len(self.alerts_df)

    @property
    def incident_count(self) -> int:
        return len(self.incidents_df)

    @property
    def all_parser_results(self) -> tuple[ParserResult, ...]:
        if self.parser_results:
            return self.parser_results
        return (self.parser_result,) if self.parser_result is not None else ()

    @property
    def quarantined_count(self) -> int:
        return sum(item.statistics.quarantined_records for item in self.all_parser_results)

    @property
    def connector_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.connector_id for item in self.all_parser_results))

    @property
    def connector_id(self) -> str | None:
        if not self.connector_ids:
            return None
        if len(self.connector_ids) == 1:
            return self.connector_ids[0]
        return "multi_source"

    @property
    def parse_success_rate(self) -> float:
        non_empty = sum(
            max(item.statistics.total_records - item.statistics.empty_records, 0)
            for item in self.all_parser_results
        )
        accepted = sum(len(item.events) for item in self.all_parser_results)
        return round(accepted / non_empty, 4) if non_empty else 0.0

    def quarantined_dataframe(self) -> pd.DataFrame:
        frames: list[pd.DataFrame] = []
        for parser_result in self.all_parser_results:
            frame = parser_result.quarantined_to_dataframe()
            if frame.empty:
                continue
            frame.insert(0, "connector_id", parser_result.connector_id)
            frame.insert(1, "source_file", parser_result.source_metadata.get("filename"))
            frames.append(frame)
        if not frames:
            return pd.DataFrame()
        return pd.concat(frames, ignore_index=True)

    def combined_parser_statistics(self) -> dict[str, Any]:
        results = self.all_parser_results
        quality_counter: Counter[str] = Counter()
        for item in results:
            quality_counter.update(item.statistics.quality_findings)
        return {
            "source_count": len(results),
            "connector_ids": list(self.connector_ids),
            "schema_version": (results[0].statistics.schema_version if results else "1.0.0"),
            "total_records": sum(item.statistics.total_records for item in results),
            "parsed_records": sum(item.statistics.parsed_records for item in results),
            "partial_records": sum(item.statistics.partial_records for item in results),
            "quarantined_records": sum(item.statistics.quarantined_records for item in results),
            "empty_records": sum(item.statistics.empty_records for item in results),
            "parse_success_rate": self.parse_success_rate,
            "quality_findings": dict(sorted(quality_counter.items())),
            "sources": [
                {
                    **item.statistics.model_dump(mode="json"),
                    "source_metadata": dict(item.source_metadata),
                }
                for item in results
            ],
            "source_manifest": [dict(item) for item in self.source_manifest],
        }


def _prepare_events(
    parser_results: list[ParserResult],
) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for parser_result in parser_results:
        frame = parser_result.to_dataframe()
        if frame.empty:
            continue
        frame["connector_id"] = parser_result.connector_id
        frame["ingest_source"] = parser_result.source_metadata.get("filename")
        frames.append(frame)
    if not frames:
        return pd.DataFrame(columns=[*COMMON_EVENT_COLUMNS, "connector_id", "ingest_source"])
    normalized_frames = [frame.dropna(axis=1, how="all") for frame in frames]
    events_df = pd.concat(normalized_frames, ignore_index=True, sort=False)
    events_df["event_id"] = range(1, len(events_df) + 1)
    return events_df


def analyze_sources(
    sources: list[SourceInput] | tuple[SourceInput, ...],
    *,
    connector_registry: ConnectorRegistry | None = None,
    rule_directory: Path = DEFAULT_RULE_DIRECTORY,
) -> AnalysisPipelineResult:
    """Normalize and analyze one or more heterogeneous telemetry sources together."""

    if not sources:
        raise ValueError("At least one telemetry source is required.")
    registry = connector_registry or build_default_connector_registry()
    parser_results: list[ParserResult] = []
    source_manifest: list[dict[str, Any]] = []

    for index, source in enumerate(sources, start=1):
        if source.connector_id:
            connector = registry.get(source.connector_id)
            validation = connector.validate_source(
                source.raw_content,
                filename=source.filename,
            )
        else:
            detection = registry.detect(source.raw_content, filename=source.filename)
            connector = detection.connector
            validation = detection.validation
        parser_result = connector.parse(
            source.raw_content,
            filename=source.filename,
            options=source.options,
        )
        parser_results.append(parser_result)
        source_manifest.append(
            {
                "source_index": index,
                "filename": source.filename,
                "connector_id": connector.metadata.connector_id,
                "validation_confidence": validation.confidence,
                "validation_reasons": list(validation.reasons),
                "event_count": len(parser_result.events),
                "quarantined_count": len(parser_result.quarantined_records),
                "parse_success_rate": parser_result.statistics.parse_success_rate,
            }
        )

    events_df = _prepare_events(parser_results)
    loader = RuleLoader(rule_directory)
    validation = loader.validation_report()
    rules = loader.load()
    alerts_df = detect_alerts(events_df, rules=rules)
    correlation_result = advanced_correlate_alerts(alerts_df, events_df)
    incidents_df = correlation_result.incidents_df
    timeline_df = build_timeline(events_df, alerts_df)
    single_parser = parser_results[0] if len(parser_results) == 1 else None
    return AnalysisPipelineResult(
        events_df=events_df,
        alerts_df=alerts_df,
        incidents_df=incidents_df,
        timeline_df=timeline_df,
        parser_result=single_parser,
        parser_results=tuple(parser_results),
        source_manifest=tuple(source_manifest),
        rule_validation=validation,
        correlation_result=correlation_result,
    )


def analyze_source(
    raw_content: str | bytes,
    *,
    filename: str | None = None,
    connector_id: str | None = None,
    connector_options: dict[str, Any] | None = None,
    connector_registry: ConnectorRegistry | None = None,
    rule_directory: Path = DEFAULT_RULE_DIRECTORY,
) -> AnalysisPipelineResult:
    """Auto-detect, normalize, detect, correlate and build a timeline."""

    return analyze_sources(
        [
            SourceInput(
                raw_content=raw_content,
                filename=filename,
                connector_id=connector_id,
                options=connector_options or {},
            )
        ],
        connector_registry=connector_registry,
        rule_directory=rule_directory,
    )


def analyze_linux_auth_log(log_text: str) -> AnalysisPipelineResult:
    """Backward-compatible Linux analysis entry point."""

    return analyze_source(
        log_text,
        filename="auth.log",
        connector_id="linux_auth",
    )
