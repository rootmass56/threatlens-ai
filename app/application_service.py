from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import yaml
from sqlalchemy.orm import Session

from api.version import THREATLENS_VERSION
from attack.service import AttackCatalogService
from core.concurrency import StripedLockRegistry
from core.connectors import build_default_connector_registry
from core.correlation_engine import AdvancedCorrelationResult
from core.pipeline import AnalysisPipelineResult, SourceInput, analyze_sources
from core.rules.fixtures import RuleFixtureRunner
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.profiles import RuleProfileLoader
from core.rules.quality import RuleQualityAnalyzer
from core.timeline_builder import build_timeline
from correlation.models import CORRELATION_VERSION
from database.exceptions import DuplicateAnalysisError
from database.service import (
    COMMON_SCHEMA_VERSION,
    ENGINE_VERSION,
    PARSER_VERSION,
    PersistedAnalysisResult,
    ThreatLensPersistenceService,
)
from database.session import session_scope

SessionContextFactory = Callable[[], AbstractContextManager[Session]]
RULE_CATALOG_VERSION = "0.7.0"
_ANALYSIS_FINGERPRINT_LOCKS = StripedLockRegistry()


@dataclass(frozen=True)
class AnalysisExecutionResult:
    """Result returned to the presentation layer after analysis."""

    pipeline: AnalysisPipelineResult
    persistence: PersistedAnalysisResult | None
    duplicate_session_uuid: str | None

    @property
    def was_persisted(self) -> bool:
        return self.persistence is not None

    @property
    def session_uuid(self) -> str | None:
        if self.persistence is not None:
            return self.persistence.session_uuid
        return self.duplicate_session_uuid


def _content_sha256(raw_content: str | bytes) -> str:
    payload = (
        raw_content.encode("utf-8", errors="replace")
        if isinstance(raw_content, str)
        else raw_content
    )
    return hashlib.sha256(payload).hexdigest()


def _rule_source_reference(source_path: str | None, rule_directory: Path) -> str | None:
    """Expose repository-relative rule provenance without leaking host filesystem paths."""

    if not source_path:
        return None
    source = Path(source_path)
    project_root = rule_directory.resolve().parent
    try:
        return source.resolve().relative_to(project_root).as_posix()
    except (OSError, ValueError):
        return source.name


def _stable_json_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _effective_rule_catalog_identity(
    rule_directory: Path,
    *,
    profile: str | None = None,
) -> dict[str, str]:
    selected_profile = (
        profile or os.getenv("THREATLENS_RULE_PROFILE", "default")
    ).strip() or "default"
    rules = RuleLoader(rule_directory).load(enabled_only=False, profile=selected_profile)
    payload = {
        "profile": selected_profile,
        "rules": [
            rule.model_dump(mode="json")
            for rule in sorted(rules, key=lambda item: item.detection_name)
        ],
    }
    return {
        "profile": selected_profile,
        "effective_rules_sha256": _stable_json_sha256(payload),
    }


def _analysis_context(
    *,
    sources: list[SourceInput],
    pipeline_result: AnalysisPipelineResult,
    rule_directory: Path,
) -> dict[str, Any]:
    parser_results = pipeline_result.all_parser_results
    source_records: list[dict[str, Any]] = []
    for index, source in enumerate(sources):
        resolved_connector = (
            parser_results[index].connector_id if index < len(parser_results) else None
        )
        source_records.append(
            {
                "source_index": index + 1,
                "filename": source.filename,
                "requested_connector_id": source.connector_id,
                "resolved_connector_id": resolved_connector,
                "options": dict(sorted((source.options or {}).items())),
                "content_sha256": _content_sha256(source.raw_content),
            }
        )
    rule_identity = _effective_rule_catalog_identity(rule_directory)
    return {
        "fingerprint_schema": "threatlens-analysis-fingerprint-1.0",
        "application_version": THREATLENS_VERSION,
        "engine_version": ENGINE_VERSION,
        "parser_version": PARSER_VERSION,
        "common_schema_version": COMMON_SCHEMA_VERSION,
        "rule_catalog_version": RULE_CATALOG_VERSION,
        "correlation_version": CORRELATION_VERSION,
        "rule_profile": rule_identity["profile"],
        "effective_rules_sha256": rule_identity["effective_rules_sha256"],
        "loaded_rule_count": (
            len(pipeline_result.rule_validation.enabled_rules)
            if pipeline_result.rule_validation is not None
            else 0
        ),
        "sources": source_records,
    }


def _persisted_loaded_rule_count(
    session_metadata: dict[str, Any],
    rule_directory: Path,
) -> int | None:
    """Return the persisted rule count only when its provenance can be proven."""

    context = dict(session_metadata.get("analysis_context") or {})
    stored_count = context.get("loaded_rule_count")
    if stored_count is not None:
        try:
            return max(int(stored_count), 0)
        except (TypeError, ValueError):
            return None

    expected_hash = str(context.get("effective_rules_sha256") or "").strip()
    profile = str(context.get("rule_profile") or "default").strip() or "default"
    if not expected_hash:
        return None

    current_identity = _effective_rule_catalog_identity(
        rule_directory,
        profile=profile,
    )
    if current_identity["effective_rules_sha256"] != expected_hash:
        return None
    return len(RuleLoader(rule_directory).load(profile=profile))


def _pipeline_from_persisted_details(
    details: dict[str, Any],
) -> AnalysisPipelineResult:
    """Rebuild database-backed analysis frames and persisted source-manifest metadata."""

    events_df = pd.DataFrame(details["events"])
    alerts_df = pd.DataFrame(details["alerts"])
    incidents_df = pd.DataFrame(details["incidents"])
    timeline_df = build_timeline(events_df, alerts_df)
    correlation_result = AdvancedCorrelationResult.from_persisted(details.get("correlation"))
    session_metadata = dict(details.get("session") or {})
    parser_statistics = dict(session_metadata.get("parser_statistics") or {})
    source_manifest = tuple(parser_statistics.get("source_manifest") or [])
    return AnalysisPipelineResult(
        events_df=events_df,
        alerts_df=alerts_df,
        incidents_df=incidents_df,
        timeline_df=timeline_df,
        source_manifest=source_manifest,
        correlation_result=correlation_result,
    )


def _hydrate_duplicate_pipeline(
    transient_pipeline: AnalysisPipelineResult,
    details: dict[str, Any],
) -> AnalysisPipelineResult:
    """Combine persisted SOC identifiers with current parser diagnostics."""

    persisted_pipeline = _pipeline_from_persisted_details(details)
    return AnalysisPipelineResult(
        events_df=persisted_pipeline.events_df,
        alerts_df=persisted_pipeline.alerts_df,
        incidents_df=persisted_pipeline.incidents_df,
        timeline_df=persisted_pipeline.timeline_df,
        parser_result=transient_pipeline.parser_result,
        parser_results=transient_pipeline.parser_results,
        source_manifest=transient_pipeline.source_manifest,
        rule_validation=transient_pipeline.rule_validation,
        correlation_result=persisted_pipeline.correlation_result,
    )


def _bundle_sources(sources: list[SourceInput]) -> bytes:
    chunks: list[bytes] = []
    for index, source in enumerate(sources, start=1):
        content = (
            source.raw_content.encode("utf-8", errors="replace")
            if isinstance(source.raw_content, str)
            else source.raw_content
        )
        header = json.dumps(
            {
                "source_index": index,
                "filename": source.filename,
                "connector_id": source.connector_id,
                "options": dict(sorted((source.options or {}).items())),
                "length": len(content),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        chunks.extend(
            [
                b"\n--THREATLENS-SOURCE-START--\n",
                header,
                b"\n",
                content,
                b"\n--THREATLENS-SOURCE-END--\n",
            ]
        )
    return b"".join(chunks)


class ThreatLensApplicationService:
    """Orchestrate connectors, rule evaluation, persistence and case management."""

    def __init__(
        self,
        session_context_factory: SessionContextFactory = session_scope,
        rule_directory: Path = DEFAULT_RULE_DIRECTORY,
    ) -> None:
        self._session_context_factory = session_context_factory
        self._rule_directory = rule_directory

    def _persist_pipeline(
        self,
        *,
        pipeline_result: AnalysisPipelineResult,
        analysis_name: str,
        original_filename: str | None,
        raw_content: str | bytes,
        source_inputs: list[SourceInput],
        actor: str,
        allow_duplicate: bool,
    ) -> AnalysisExecutionResult:
        statistics = pipeline_result.combined_parser_statistics()
        analysis_context = _analysis_context(
            sources=source_inputs,
            pipeline_result=pipeline_result,
            rule_directory=self._rule_directory,
        )
        analysis_fingerprint = _stable_json_sha256(analysis_context)
        source_type = pipeline_result.connector_id or "unknown"
        gate = (
            _ANALYSIS_FINGERPRINT_LOCKS.lock_for(analysis_fingerprint)
            if not allow_duplicate
            else nullcontext()
        )
        # Current SQLite/demo deployments are single-process. Hold the keyed gate through
        # transaction commit so concurrent identical uploads cannot both pass the
        # check-then-insert duplicate test. PostgreSQL/distributed idempotency is a later
        # operational milestone.
        with gate:
            with self._session_context_factory() as database_session:
                service = ThreatLensPersistenceService(database_session)
                try:
                    persisted = service.persist_analysis(
                        analysis_name=analysis_name,
                        source_type=source_type,
                        connector_id=source_type,
                        schema_version=str(statistics.get("schema_version", "1.0.0")),
                        rule_catalog_version=RULE_CATALOG_VERSION,
                        original_filename=original_filename,
                        raw_content=raw_content,
                        events_df=pipeline_result.events_df,
                        alerts_df=pipeline_result.alerts_df,
                        incidents_df=pipeline_result.incidents_df,
                        parser_statistics=statistics,
                        correlation_result=pipeline_result.correlation_result,
                        analysis_fingerprint=analysis_fingerprint,
                        analysis_context=analysis_context,
                        actor=actor,
                        allow_duplicate=allow_duplicate,
                    )
                    return AnalysisExecutionResult(
                        pipeline=pipeline_result,
                        persistence=persisted,
                        duplicate_session_uuid=None,
                    )
                except DuplicateAnalysisError as error:
                    details = service.get_analysis_details(error.existing_session_uuid)
                    hydrated_pipeline = (
                        _hydrate_duplicate_pipeline(pipeline_result, details)
                        if details is not None
                        else pipeline_result
                    )
                    return AnalysisExecutionResult(
                        pipeline=hydrated_pipeline,
                        persistence=None,
                        duplicate_session_uuid=error.existing_session_uuid,
                    )

    def analyze_and_persist_source(
        self,
        *,
        analysis_name: str,
        original_filename: str | None,
        raw_content: str | bytes,
        connector_id: str | None = None,
        connector_options: dict[str, Any] | None = None,
        actor: str = "system",
        allow_duplicate: bool = False,
    ) -> AnalysisExecutionResult:
        source = SourceInput(
            raw_content=raw_content,
            filename=original_filename,
            connector_id=connector_id,
            options=connector_options or {},
        )
        pipeline_result = analyze_sources(
            [source],
            rule_directory=self._rule_directory,
        )
        return self._persist_pipeline(
            pipeline_result=pipeline_result,
            analysis_name=analysis_name,
            original_filename=original_filename,
            raw_content=raw_content,
            source_inputs=[source],
            actor=actor,
            allow_duplicate=allow_duplicate,
        )

    def analyze_and_persist_sources(
        self,
        *,
        analysis_name: str,
        sources: list[SourceInput],
        actor: str = "system",
        allow_duplicate: bool = False,
    ) -> AnalysisExecutionResult:
        """Analyze heterogeneous files as one evidence-preserving SOC session."""

        pipeline_result = analyze_sources(
            sources,
            rule_directory=self._rule_directory,
        )
        names = [source.filename or f"source-{index}" for index, source in enumerate(sources, 1)]
        return self._persist_pipeline(
            pipeline_result=pipeline_result,
            analysis_name=analysis_name,
            original_filename="; ".join(names),
            raw_content=_bundle_sources(sources),
            source_inputs=list(sources),
            actor=actor,
            allow_duplicate=allow_duplicate,
        )

    def analyze_and_persist_linux_log(
        self,
        *,
        analysis_name: str,
        original_filename: str | None,
        log_text: str,
        raw_content: str | bytes | None = None,
        actor: str = "system",
        allow_duplicate: bool = False,
    ) -> AnalysisExecutionResult:
        content = raw_content if raw_content is not None else log_text
        return self.analyze_and_persist_source(
            analysis_name=analysis_name,
            original_filename=original_filename,
            raw_content=content,
            connector_id="linux_auth",
            actor=actor,
            allow_duplicate=allow_duplicate,
        )

    def get_connector_catalog(self) -> pd.DataFrame:
        registry = build_default_connector_registry()
        frame = pd.DataFrame(registry.metadata())
        rules = RuleLoader(self._rule_directory).validation_report().rules
        counts: dict[str, int] = {}
        for rule in rules:
            dataset = rule.logsource.dataset or ""
            counts[dataset] = counts.get(dataset, 0) + 1
        if not frame.empty:
            frame["status"] = "registered"
            frame["rule_count"] = frame["connector_id"].map(counts).fillna(0).astype(int)
        return frame

    def get_connector_diagnostics(
        self,
        *,
        raw_content: str | bytes,
        filename: str | None,
    ) -> pd.DataFrame:
        registry = build_default_connector_registry()
        return pd.DataFrame(
            [
                {
                    "connector_id": item.connector.metadata.connector_id,
                    "name": item.connector.metadata.name,
                    "valid": item.validation.valid,
                    "confidence": item.validation.confidence,
                    "reasons": " | ".join(item.validation.reasons),
                }
                for item in registry.diagnostics(raw_content, filename=filename)
            ]
        )

    def get_rule_catalog(self) -> pd.DataFrame:
        report = RuleLoader(self._rule_directory).validation_report()
        rows: list[dict[str, Any]] = []
        for rule in report.rules:
            manifest_path = self._rule_directory / rule.fixtures.manifest
            fixture_count = 0
            if manifest_path.exists():
                payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig")) or {}
                fixture_count = len(payload.get("cases", []))
            rows.append(
                {
                    "rule_id": rule.rule_id,
                    "detection_name": rule.detection_name,
                    "title": rule.title,
                    "version": rule.version,
                    "status": rule.status.value,
                    "enabled": rule.enabled,
                    "kind": rule.kind.value,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "product": rule.logsource.product,
                    "service": rule.logsource.service,
                    "dataset": rule.logsource.dataset,
                    "primary_technique_id": rule.primary_attack.technique_id,
                    "primary_technique": rule.primary_attack.technique,
                    "primary_tactic": rule.primary_attack.tactic,
                    "attack_mapping_count": len(rule.attack),
                    "fixture_count": fixture_count,
                    "playbook": rule.response.playbook,
                    "owner": rule.lifecycle.owner,
                    "reviewers": ", ".join(rule.lifecycle.reviewers),
                    "last_reviewed": rule.lifecycle.last_reviewed,
                    "review_interval_days": rule.lifecycle.review_interval_days,
                    "changelog_entries": len(rule.lifecycle.changelog),
                    "allowlist_count": len(rule.tuning.allowlists),
                    "suppression_enabled": rule.tuning.suppression.enabled,
                    "suppression_group_by": ", ".join(rule.tuning.suppression.group_by),
                    "source_path": _rule_source_reference(
                        report.source_paths.get(rule.rule_id), self._rule_directory
                    ),
                }
            )
        return pd.DataFrame(rows)

    def get_rule_validation(self) -> dict[str, Any]:
        report = RuleLoader(self._rule_directory).validation_report()
        return {
            **report.summary(),
            "issues_detail": [
                {
                    "path": issue.path,
                    "severity": issue.severity,
                    "message": issue.message,
                }
                for issue in report.issues
            ],
        }

    def get_rule_fixture_results(self) -> pd.DataFrame:
        """Execute and return positive, negative and boundary fixture evidence."""

        return pd.DataFrame(RuleFixtureRunner(self._rule_directory).run().records())

    def get_rule_quality_summary(self) -> dict[str, Any]:
        """Return governed catalogue coverage and lifecycle metrics."""

        summary = RuleQualityAnalyzer(self._rule_directory).summary()
        return {"catalog_version": RULE_CATALOG_VERSION, **summary.__dict__}

    def get_rule_quality_records(self) -> pd.DataFrame:
        """Return per-rule governance, review and fixture evidence."""

        return pd.DataFrame(RuleQualityAnalyzer(self._rule_directory).records_as_dicts())

    def get_rule_profiles(self) -> pd.DataFrame:
        """Return available environment-specific tuning profiles."""

        loader = RuleLoader(self._rule_directory)
        return pd.DataFrame(
            [item.__dict__ for item in RuleProfileLoader(loader.profile_path).available_profiles()]
        )

    def synchronize_attack_catalog(
        self,
        *,
        actor: str = "system",
        force_download: bool = False,
    ) -> dict[str, Any]:
        """Download and atomically synchronize the complete pinned ATT&CK release."""

        results = AttackCatalogService(
            self._session_context_factory,
            self._rule_directory,
        ).synchronize_all(
            allow_network=True,
            force_download=force_download,
            actor=actor,
        )
        return {"domains": [item.as_dict() for item in results]}

    def get_attack_catalog_status(
        self,
        domain: str = "enterprise-attack",
    ) -> dict[str, Any] | None:
        return AttackCatalogService(
            self._session_context_factory,
            self._rule_directory,
        ).active_status(domain)

    def get_attack_catalog_statuses(self) -> pd.DataFrame:
        return pd.DataFrame(
            AttackCatalogService(
                self._session_context_factory,
                self._rule_directory,
            ).active_statuses()
        )

    def get_attack_techniques(
        self,
        domain: str = "enterprise-attack",
    ) -> pd.DataFrame:
        return pd.DataFrame(
            AttackCatalogService(
                self._session_context_factory,
                self._rule_directory,
            ).technique_rows(domain)
        )

    def get_attack_rule_mappings(self) -> pd.DataFrame:
        return pd.DataFrame(
            AttackCatalogService(
                self._session_context_factory,
                self._rule_directory,
            ).mapping_rows()
        )

    def get_attack_object_types(
        self,
        domain: str = "enterprise-attack",
    ) -> pd.DataFrame:
        return pd.DataFrame(
            AttackCatalogService(
                self._session_context_factory,
                self._rule_directory,
            ).object_type_rows(domain)
        )

    def get_attack_navigator_json(self) -> bytes:
        return AttackCatalogService(
            self._session_context_factory,
            self._rule_directory,
        ).navigator_json()

    def get_correlation_summary(self, session_uuid: str) -> dict[str, Any] | None:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        if details is None:
            return None
        correlation = details.get("correlation")
        if not correlation:
            return None
        return {
            "version": correlation.get("version"),
            "correlation_uuid": correlation.get("correlation_uuid"),
            "policy": correlation.get("policy") or {},
            "metrics": correlation.get("metrics") or {},
            "graph_sha256": correlation.get("graph_sha256"),
        }

    def get_correlation_entities(self, session_uuid: str) -> pd.DataFrame:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        correlation = details.get("correlation") if details else None
        return pd.DataFrame((correlation or {}).get("entities") or [])

    def get_correlation_relationships(self, session_uuid: str) -> pd.DataFrame:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        correlation = details.get("correlation") if details else None
        return pd.DataFrame((correlation or {}).get("relationships") or [])

    def get_attack_graph(self, session_uuid: str) -> dict[str, Any] | None:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        correlation = details.get("correlation") if details else None
        if not correlation:
            return None
        return correlation.get("graph") or None

    def get_rule_details(self, rule_id: str) -> dict[str, Any] | None:
        report = RuleLoader(self._rule_directory).validation_report()
        for rule in report.rules:
            if rule.rule_id == rule_id:
                return {
                    **rule.model_dump(mode="json"),
                    "source_path": _rule_source_reference(
                        report.source_paths.get(rule.rule_id), self._rule_directory
                    ),
                }
        return None

    def get_analysis_history(self, limit: int = 100) -> pd.DataFrame:
        with self._session_context_factory() as database_session:
            records = ThreatLensPersistenceService(database_session).list_analysis_history(
                limit=limit
            )
        return pd.DataFrame(records)

    def load_analysis(self, session_uuid: str) -> AnalysisPipelineResult | None:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        if details is None:
            return None
        return _pipeline_from_persisted_details(details)

    def get_analysis_metadata(self, session_uuid: str) -> dict[str, Any] | None:
        with self._session_context_factory() as database_session:
            details = ThreatLensPersistenceService(database_session).get_analysis_details(
                session_uuid
            )
        if details is None:
            return None
        metadata = dict(details["session"])
        metadata["loaded_rule_count"] = _persisted_loaded_rule_count(
            metadata,
            self._rule_directory,
        )
        return metadata

    def get_incident_queue(
        self,
        *,
        status: str | None = None,
        limit: int = 250,
    ) -> pd.DataFrame:
        with self._session_context_factory() as database_session:
            records = ThreatLensPersistenceService(database_session).list_incident_cases(
                status=status,
                limit=limit,
            )
        return pd.DataFrame(records)

    def get_incident_details(self, incident_uuid: str) -> dict[str, Any] | None:
        with self._session_context_factory() as database_session:
            return ThreatLensPersistenceService(database_session).get_incident_details(
                incident_uuid
            )

    def update_incident(
        self,
        *,
        incident_uuid: str,
        status: str,
        assignee: str | None,
        priority: str | None,
        actor: str,
    ) -> None:
        with self._session_context_factory() as database_session:
            ThreatLensPersistenceService(database_session).update_incident_workflow(
                incident_uuid=incident_uuid,
                status=status,
                assignee=assignee,
                priority=priority,
                actor=actor,
            )

    def add_incident_note(
        self,
        *,
        incident_uuid: str,
        author: str,
        note: str,
    ) -> str:
        with self._session_context_factory() as database_session:
            return ThreatLensPersistenceService(database_session).add_investigation_note(
                incident_uuid=incident_uuid,
                author=author,
                note=note,
            )

    def register_incident_evidence(
        self,
        *,
        incident_uuid: str,
        evidence_type: str,
        description: str,
        source_reference: str | None,
        sha256: str | None,
        actor: str,
    ) -> str:
        with self._session_context_factory() as database_session:
            return ThreatLensPersistenceService(database_session).register_evidence(
                incident_uuid=incident_uuid,
                evidence_type=evidence_type,
                description=description,
                source_reference=source_reference,
                sha256=sha256,
                actor=actor,
            )

    def get_audit_logs(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 500,
    ) -> pd.DataFrame:
        with self._session_context_factory() as database_session:
            records = ThreatLensPersistenceService(database_session).list_audit_logs(
                entity_type=entity_type,
                entity_id=entity_id,
                limit=limit,
            )
        return pd.DataFrame(records)

    def get_persistent_metrics(self) -> dict[str, Any]:
        history_df = self.get_analysis_history(limit=10_000)
        incidents_df = self.get_incident_queue(limit=10_000)
        metrics: dict[str, Any] = {
            "total_analyses": 0,
            "total_events": 0,
            "total_alerts": 0,
            "total_incidents": 0,
            "total_quarantined": 0,
            "open_incidents": 0,
            "critical_incidents": 0,
            "investigating_incidents": 0,
            "resolved_incidents": 0,
            "false_positive_incidents": 0,
        }
        if not history_df.empty:
            metrics.update(
                {
                    "total_analyses": len(history_df),
                    "total_events": int(history_df["events"].sum()),
                    "total_alerts": int(history_df["alerts"].sum()),
                    "total_incidents": int(history_df["incidents"].sum()),
                    "total_quarantined": int(history_df.get("quarantined", 0).sum()),
                }
            )
        if not incidents_df.empty:
            status = incidents_df["status"]
            metrics.update(
                {
                    "open_incidents": int((status == "open").sum()),
                    "critical_incidents": int((incidents_df["severity"] == "Critical").sum()),
                    "investigating_incidents": int((status == "investigating").sum()),
                    "resolved_incidents": int((status == "resolved").sum()),
                    "false_positive_incidents": int((status == "false_positive").sum()),
                }
            )
        return metrics
