
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

import pandas as pd
from sqlalchemy.orm import Session

from core.case_workflow import (
    ALLOWED_STATUS_TRANSITIONS,
    VALID_INCIDENT_STATUSES,
    VALID_PRIORITIES,
)
from correlation.models import AdvancedCorrelationResult
from database.exceptions import (
    DuplicateAnalysisError,
    IncidentNotFoundError,
    InvalidIncidentStateError,
)
from database.models import (
    AlertModel,
    AnalysisSessionModel,
    AttackGraphSnapshotModel,
    AuditLogModel,
    CorrelationEntityModel,
    CorrelationRelationshipModel,
    CorrelationRunModel,
    EventModel,
    EvidenceModel,
    IncidentModel,
    InvestigationNoteModel,
    incident_entities,
    utc_now,
)
from database.repositories import (
    AnalysisSessionRepository,
    AuditLogRepository,
    IncidentRepository,
)

ENGINE_VERSION = "0.8.0"
PARSER_VERSION = "1.0.0"
COMMON_SCHEMA_VERSION = "1.0.0"
RULE_CATALOG_VERSION = "0.7.0"

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class PersistedAnalysisResult:
    """Summary returned after persisting an analysis."""

    session_uuid: str
    event_count: int
    alert_count: int
    incident_count: int
    file_sha256: str
    analysis_fingerprint: str
    quarantined_count: int = 0
    parse_success_rate: float = 0.0


def _clean_scalar(value: Any) -> Any:
    if value is None:
        return None
    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        missing = False
    if isinstance(missing, bool) and missing:
        return None
    return value


def _clean_text(value: Any) -> str | None:
    cleaned = _clean_scalar(value)
    if cleaned is None:
        return None
    text = str(cleaned).strip()
    return text or None


def _to_datetime(value: Any) -> datetime | None:
    cleaned = _clean_scalar(value)
    if cleaned is None:
        return None
    parsed = pd.to_datetime(cleaned, errors="coerce", utc=True)
    if pd.isna(parsed):
        return None
    return parsed.to_pydatetime()


def _stable_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _dataframe_records(frame: pd.DataFrame) -> list[dict[str, Any]]:
    if frame.empty:
        return []
    return json.loads(frame.to_json(orient="records", date_format="iso"))


def calculate_content_sha256(raw_content: str | bytes) -> str:
    """Calculate the SHA-256 hash of uploaded or registered content."""

    content_bytes = (
        raw_content.encode("utf-8", errors="replace")
        if isinstance(raw_content, str)
        else raw_content
    )
    return hashlib.sha256(content_bytes).hexdigest()


def _risk_priority(risk_score: int) -> str:
    if risk_score >= 90:
        return "P1"
    if risk_score >= 70:
        return "P2"
    if risk_score >= 40:
        return "P3"
    return "P4"


def _confidence_from_severity(severity: str) -> float:
    return {
        "Critical": 0.95,
        "High": 0.85,
        "Medium": 0.70,
        "Low": 0.50,
    }.get(severity, 0.50)


def _int_list(value: Any) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        result: list[int] = []
        for item in value:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
        return result
    text = _clean_text(value)
    if not text:
        return []
    result = []
    for item in text.strip("[]").split(","):
        try:
            result.append(int(item.strip()))
        except ValueError:
            continue
    return result


class ThreatLensPersistenceService:
    """Transactional persistence and case-management service."""

    def __init__(self, database_session: Session) -> None:
        self.database_session = database_session
        self.analysis_repository = AnalysisSessionRepository(database_session)
        self.incident_repository = IncidentRepository(database_session)
        self.audit_repository = AuditLogRepository(database_session)

    def _write_audit_log(
        self,
        *,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.database_session.add(
            AuditLogModel(
                actor=actor.strip() or "unknown",
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details_json=details or {},
            )
        )

    def record_audit_event(
        self,
        *,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an append-only auditable platform action."""

        self._write_audit_log(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )

    def _create_event_model(
        self,
        analysis_session_id: int,
        row: pd.Series,
    ) -> EventModel:
        fingerprint_payload = {
            "event_uuid": _clean_text(row.get("event_uuid")),
            "timestamp": _clean_text(row.get("timestamp")),
            "source_dataset": _clean_text(row.get("source_dataset")),
            "event_type": _clean_text(row.get("event_type")),
            "source_ip": _clean_text(row.get("source_ip")),
            "destination_ip": _clean_text(row.get("destination_ip")),
            "username": _clean_text(row.get("username")),
            "hostname": _clean_text(row.get("hostname")),
            "raw_message": _clean_text(row.get("raw_message")),
        }
        attributes = _clean_scalar(row.get("attributes"))
        if not isinstance(attributes, dict):
            attributes = _clean_scalar(row.get("attributes_json"))
        if not isinstance(attributes, dict):
            attributes = {}
        quality = _clean_scalar(row.get("data_quality"))
        if not isinstance(quality, list):
            quality = []
        event_uuid = _clean_text(row.get("event_uuid")) or str(uuid4())
        return EventModel(
            event_uuid=event_uuid,
            analysis_session_id=analysis_session_id,
            external_event_id=_clean_text(row.get("event_id")),
            event_fingerprint=_stable_sha256(fingerprint_payload),
            timestamp=_to_datetime(row.get("timestamp")),
            schema_version=_clean_text(row.get("schema_version")) or COMMON_SCHEMA_VERSION,
            original_timestamp=_clean_text(row.get("original_timestamp")),
            timezone=_clean_text(row.get("timezone")),
            source_type=_clean_text(row.get("source_type")) or "unknown",
            source_category=_clean_text(row.get("source_category")),
            source_product=_clean_text(row.get("source_product")),
            source_service=_clean_text(row.get("source_service")),
            source_dataset=_clean_text(row.get("source_dataset")),
            process_name=_clean_text(row.get("process_name")),
            process_id=_clean_scalar(row.get("process_id")),
            parent_process_name=_clean_text(row.get("parent_process_name")),
            command_line=_clean_text(row.get("command_line")),
            source_ip=_clean_text(row.get("source_ip")),
            source_port=_clean_scalar(row.get("source_port")),
            destination_ip=_clean_text(row.get("destination_ip")),
            destination_port=_clean_scalar(row.get("destination_port")),
            username=_clean_text(row.get("username")),
            hostname=_clean_text(row.get("hostname")),
            event_type=_clean_text(row.get("event_type")) or "unknown",
            event_action=_clean_text(row.get("event_action")),
            event_outcome=_clean_text(row.get("event_outcome")),
            file_path=_clean_text(row.get("file_path")),
            domain=_clean_text(row.get("domain")),
            url=_clean_text(row.get("url")),
            parser_name=_clean_text(row.get("parser_name")),
            parser_version=_clean_text(row.get("parser_version")),
            parse_status=_clean_text(row.get("parse_status")) or "parsed",
            data_quality_json=quality,
            raw_message=_clean_text(row.get("raw_message")) or "",
            normalized_message=_clean_text(row.get("normalized_message")) or "",
            attributes_json=attributes,
        )

    def _create_alert_model(
        self,
        analysis_session_id: int,
        row: pd.Series,
        event_lookup: dict[str, EventModel],
    ) -> AlertModel:
        event_reference = _clean_text(row.get("event_id"))
        primary_event = event_lookup.get(event_reference or "")
        detection_name = _clean_text(row.get("detection_name")) or "unknown_detection"
        severity = _clean_text(row.get("severity")) or "Low"
        risk_score = int(_clean_scalar(row.get("risk_score")) or 0)
        confidence = float(
            _clean_scalar(row.get("confidence")) or _confidence_from_severity(severity)
        )
        tactic = _clean_text(row.get("mitre_tactic"))
        technique = _clean_text(row.get("mitre_technique"))
        technique_id = _clean_text(row.get("mitre_technique_id"))
        mappings = _clean_scalar(row.get("attack_mappings"))
        if not isinstance(mappings, list):
            mappings = []
        if not mappings and technique_id and technique_id != "N/A":
            mappings.append(
                {
                    "role": "primary",
                    "tactic": tactic,
                    "technique": technique,
                    "technique_id": technique_id,
                    "confidence": confidence,
                    "justification": _clean_text(row.get("description")),
                }
            )
        fingerprint_payload = {
            "detection_name": detection_name,
            "timestamp": _clean_text(row.get("timestamp")),
            "source_ip": _clean_text(row.get("source_ip")),
            "username": _clean_text(row.get("username")),
            "hostname": _clean_text(row.get("hostname")),
            "description": _clean_text(row.get("description")),
        }
        alert = AlertModel(
            alert_uuid=str(uuid4()),
            analysis_session_id=analysis_session_id,
            event_id=primary_event.id if primary_event else None,
            alert_fingerprint=_stable_sha256(fingerprint_payload),
            detection_id=_clean_text(row.get("rule_id")) or detection_name,
            rule_id=_clean_text(row.get("rule_id")),
            rule_title=_clean_text(row.get("rule_title")),
            rule_status=_clean_text(row.get("rule_status")),
            detection_name=detection_name,
            detection_version=_clean_text(row.get("detection_version")) or "1",
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            status="open",
            description=_clean_text(row.get("description")) or detection_name,
            recommendation=_clean_text(row.get("recommendation")),
            playbook=_clean_text(row.get("playbook")),
            risk_factors_json=(
                _clean_scalar(row.get("risk_factors"))
                if isinstance(_clean_scalar(row.get("risk_factors")), dict)
                else {}
            ),
            risk_policy_version=_clean_text(row.get("risk_policy_version")),
            primary_tactic=tactic,
            primary_technique_id=technique_id,
            attack_mappings_json=mappings,
            source_ip=_clean_text(row.get("source_ip")),
            username=_clean_text(row.get("username")),
            hostname=_clean_text(row.get("hostname")),
            event_count=int(_clean_scalar(row.get("event_count")) or 1),
            timestamp=_to_datetime(row.get("timestamp")),
        )
        supporting_ids = _int_list(row.get("supporting_event_ids"))
        evidence_events = [
            event_lookup[str(external_id)]
            for external_id in supporting_ids
            if str(external_id) in event_lookup
        ]
        if primary_event is not None and primary_event not in evidence_events:
            evidence_events.append(primary_event)
        alert.evidence_events.extend(evidence_events)
        return alert

    @staticmethod
    def _create_incident_model(
        analysis_session_id: int,
        row: pd.Series,
        alert_lookup: dict[int, AlertModel],
    ) -> IncidentModel:
        risk_score = int(_clean_scalar(row.get("risk_score")) or 0)
        severity = _clean_text(row.get("severity")) or "Low"
        title = _clean_text(row.get("incident_name")) or "Suspicious Security Activity"
        confidence = float(
            _clean_scalar(row.get("confidence")) or _confidence_from_severity(severity)
        )
        incident = IncidentModel(
            incident_uuid=str(uuid4()),
            analysis_session_id=analysis_session_id,
            title=title,
            category=title,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            priority=_risk_priority(risk_score),
            status="open",
            source_ip=_clean_text(row.get("source_ip")),
            summary=_clean_text(row.get("summary")) or title,
            correlation_id=_clean_text(row.get("correlation_id")),
            correlation_version=_clean_text(row.get("correlation_version")),
            representative_alert_count=int(
                _clean_scalar(row.get("representative_alert_count")) or 0
            ),
            deduplicated_alert_count=int(_clean_scalar(row.get("deduplicated_alert_count")) or 0),
            source_count=int(_clean_scalar(row.get("source_count")) or 0),
            entity_count=int(_clean_scalar(row.get("entity_count")) or 0),
            relationship_count=int(_clean_scalar(row.get("relationship_count")) or 0),
            stage_count=int(_clean_scalar(row.get("stage_count")) or 0),
            stage_progression=_clean_text(row.get("stage_progression")),
            graph_score=float(_clean_scalar(row.get("graph_score")) or 0.0),
            storyline=_clean_text(row.get("storyline")),
            correlation_metadata_json={
                "detections": _clean_text(row.get("detections")),
                "entities": (
                    _clean_scalar(row.get("entities"))
                    if isinstance(_clean_scalar(row.get("entities")), dict)
                    else {}
                ),
            },
            start_time=_to_datetime(row.get("start_time")),
            end_time=_to_datetime(row.get("end_time")),
        )
        for alert_id in _int_list(row.get("alert_ids")):
            alert = alert_lookup.get(alert_id)
            if alert is not None:
                incident.alerts.append(alert)
        return incident

    def _persist_correlation(
        self,
        *,
        analysis_session: AnalysisSessionModel,
        incident_lookup: dict[int, IncidentModel],
        correlation_result: AdvancedCorrelationResult,
    ) -> None:
        metrics = dict(correlation_result.metrics)
        metrics["deduplicated_alerts_detail"] = _dataframe_records(
            correlation_result.deduplicated_alerts_df
        )
        run = CorrelationRunModel(
            correlation_uuid=str(uuid4()),
            analysis_session_id=analysis_session.id,
            algorithm_version=correlation_result.version,
            policy_json=correlation_result.policy.as_dict(),
            input_alerts=int(metrics.get("input_alerts", 0)),
            representative_alerts=int(metrics.get("representative_alerts", 0)),
            deduplicated_alerts=int(metrics.get("deduplicated_alerts", 0)),
            duplicate_groups=int(metrics.get("duplicate_groups", 0)),
            entity_count=int(metrics.get("entities", 0)),
            relationship_count=int(metrics.get("relationships", 0)),
            incident_count=int(metrics.get("incidents", 0)),
            graph_node_count=int(metrics.get("graph_nodes", 0)),
            graph_edge_count=int(metrics.get("graph_edges", 0)),
            metrics_json=metrics,
        )
        self.database_session.add(run)
        self.database_session.flush()

        entity_lookup: dict[str, CorrelationEntityModel] = {}
        for _, row in correlation_result.entities_df.iterrows():
            key = _clean_text(row.get("entity_key"))
            if not key:
                continue
            model = CorrelationEntityModel(
                entity_uuid=str(uuid4()),
                correlation_run_id=run.id,
                entity_key=key,
                entity_type=_clean_text(row.get("entity_type")) or "unknown",
                canonical_value=_clean_text(row.get("canonical_value")) or key,
                display_value=_clean_text(row.get("display_value")) or key,
                confidence=float(_clean_scalar(row.get("confidence")) or 0.5),
                aliases_json=list(_clean_scalar(row.get("aliases")) or []),
                source_datasets_json=list(_clean_scalar(row.get("source_datasets")) or []),
                evidence_alert_ids_json=_int_list(row.get("evidence_alert_ids")),
                evidence_event_ids_json=_int_list(row.get("evidence_event_ids")),
                first_seen=_to_datetime(row.get("first_seen")),
                last_seen=_to_datetime(row.get("last_seen")),
            )
            self.database_session.add(model)
            entity_lookup[key] = model
        self.database_session.flush()

        association_rows: list[dict[str, Any]] = []
        if not correlation_result.entities_df.empty:
            for _, row in correlation_result.entities_df.iterrows():
                key = _clean_text(row.get("entity_key"))
                entity = entity_lookup.get(key or "")
                if entity is None:
                    continue
                for external_incident_id in _int_list(row.get("incident_ids")):
                    incident = incident_lookup.get(external_incident_id)
                    if incident is None:
                        continue
                    entity_type = _clean_text(row.get("entity_type")) or "related"
                    role = {
                        "username": "identity",
                        "hostname": "asset",
                        "ip": "network_indicator",
                        "process": "process_artifact",
                        "domain": "network_indicator",
                        "file": "file_artifact",
                        "hash": "file_indicator",
                        "url": "network_indicator",
                    }.get(entity_type, "related")
                    association_rows.append(
                        {
                            "incident_id": incident.id,
                            "entity_id": entity.id,
                            "role": role,
                            "confidence": float(_clean_scalar(row.get("confidence")) or 0.5),
                            "evidence_count": len(_int_list(row.get("evidence_alert_ids"))),
                        }
                    )
        if association_rows:
            self.database_session.execute(incident_entities.insert(), association_rows)

        for _, row in correlation_result.relationships_df.iterrows():
            incident_ids = _int_list(row.get("incident_ids"))
            incident = incident_lookup.get(incident_ids[0]) if len(incident_ids) == 1 else None
            source_alert_id = int(_clean_scalar(row.get("source_alert_id")) or 0)
            target_alert_id = int(_clean_scalar(row.get("target_alert_id")) or 0)
            self.database_session.add(
                CorrelationRelationshipModel(
                    relationship_uuid=str(uuid4()),
                    correlation_run_id=run.id,
                    incident_id=incident.id if incident is not None else None,
                    source_node_key=f"alert:{source_alert_id}",
                    target_node_key=f"alert:{target_alert_id}",
                    relationship_type=(_clean_text(row.get("relationship_type")) or "related"),
                    confidence=float(_clean_scalar(row.get("confidence")) or 0.0),
                    shared_entity_count=int(_clean_scalar(row.get("shared_entity_count")) or 0),
                    cluster_eligible=bool(row.get("cluster_eligible")),
                    reasons_json=list(_clean_scalar(row.get("reasons")) or []),
                    shared_entities_json=list(_clean_scalar(row.get("shared_entities")) or []),
                    evidence_alert_ids_json=[source_alert_id, target_alert_id],
                    time_delta_seconds=(
                        float(row.get("time_delta_seconds"))
                        if _clean_scalar(row.get("time_delta_seconds")) is not None
                        else None
                    ),
                )
            )

        graph_payload = correlation_result.graph_payload()
        self.database_session.add(
            AttackGraphSnapshotModel(
                graph_uuid=str(uuid4()),
                correlation_run_id=run.id,
                graph_schema=str(graph_payload.get("schema")),
                graph_sha256=correlation_result.graph_sha256,
                node_count=len(correlation_result.graph_nodes_df),
                edge_count=len(correlation_result.graph_edges_df),
                graph_json=graph_payload,
            )
        )

    def persist_analysis(
        self,
        *,
        analysis_name: str,
        source_type: str,
        original_filename: str | None,
        raw_content: str | bytes,
        events_df: pd.DataFrame,
        alerts_df: pd.DataFrame,
        incidents_df: pd.DataFrame,
        actor: str = "system",
        allow_duplicate: bool = False,
        connector_id: str | None = None,
        schema_version: str = COMMON_SCHEMA_VERSION,
        rule_catalog_version: str = RULE_CATALOG_VERSION,
        parser_statistics: dict[str, Any] | None = None,
        correlation_result: AdvancedCorrelationResult | None = None,
        analysis_fingerprint: str | None = None,
        analysis_context: dict[str, Any] | None = None,
    ) -> PersistedAnalysisResult:
        """Persist one complete analysis in the caller's transaction."""

        file_sha256 = calculate_content_sha256(raw_content)
        context = dict(analysis_context or {})
        fingerprint = analysis_fingerprint or _stable_sha256(
            {
                "content_sha256": file_sha256,
                "source_type": source_type,
                "connector_id": connector_id or source_type,
                "schema_version": schema_version,
                "parser_version": PARSER_VERSION,
                "engine_version": ENGINE_VERSION,
                "rule_catalog_version": rule_catalog_version,
            }
        )
        if not allow_duplicate:
            duplicate = self.analysis_repository.find_duplicate(fingerprint)
            if duplicate is not None:
                raise DuplicateAnalysisError(duplicate.session_uuid)

        analysis_session = AnalysisSessionModel(
            session_uuid=str(uuid4()),
            name=analysis_name.strip() or "Unnamed Analysis",
            status="processing",
            source_type=source_type,
            connector_id=connector_id or source_type,
            schema_version=schema_version,
            rule_catalog_version=rule_catalog_version,
            original_filename=original_filename,
            file_sha256=file_sha256,
            analysis_fingerprint=fingerprint,
            analysis_context_json=context,
            parser_version=PARSER_VERSION,
            engine_version=ENGINE_VERSION,
            started_at=utc_now(),
        )
        self.database_session.add(analysis_session)
        self.database_session.flush()

        event_lookup: dict[str, EventModel] = {}
        event_models: list[EventModel] = []
        for _, row in events_df.iterrows():
            model = self._create_event_model(analysis_session.id, row)
            self.database_session.add(model)
            event_models.append(model)
        self.database_session.flush()
        for model in event_models:
            if model.external_event_id:
                event_lookup[model.external_event_id] = model

        alert_lookup: dict[int, AlertModel] = {}
        alert_models: list[AlertModel] = []
        for _, row in alerts_df.iterrows():
            model = self._create_alert_model(analysis_session.id, row, event_lookup)
            self.database_session.add(model)
            alert_models.append(model)
            try:
                alert_lookup[int(row.get("alert_id"))] = model
            except (TypeError, ValueError):
                alert_lookup[len(alert_models)] = model
        self.database_session.flush()

        incident_models: list[IncidentModel] = []
        incident_lookup: dict[int, IncidentModel] = {}
        for _, row in incidents_df.iterrows():
            model = self._create_incident_model(analysis_session.id, row, alert_lookup)
            self.database_session.add(model)
            incident_models.append(model)
            try:
                incident_lookup[int(row.get("incident_id"))] = model
            except (TypeError, ValueError):
                incident_lookup[len(incident_models)] = model
        self.database_session.flush()
        if correlation_result is not None:
            self._persist_correlation(
                analysis_session=analysis_session,
                incident_lookup=incident_lookup,
                correlation_result=correlation_result,
            )

        analysis_session.total_events = len(event_models)
        analysis_session.total_alerts = len(alert_models)
        statistics = parser_statistics or {}
        analysis_session.total_incidents = len(incident_models)
        analysis_session.total_quarantined = int(statistics.get("quarantined_records", 0))
        analysis_session.parse_success_rate = float(statistics.get("parse_success_rate", 0.0))
        analysis_session.parser_statistics_json = statistics
        analysis_session.status = "completed"
        analysis_session.completed_at = utc_now()
        self._write_audit_log(
            actor=actor,
            action="analysis.persisted",
            entity_type="analysis_session",
            entity_id=analysis_session.session_uuid,
            details={
                "source_type": source_type,
                "filename": original_filename,
                "file_sha256": file_sha256,
                "analysis_fingerprint": fingerprint,
                "analysis_context": context,
                "events": len(event_models),
                "alerts": len(alert_models),
                "incidents": len(incident_models),
                "quarantined": analysis_session.total_quarantined,
                "parse_success_rate": analysis_session.parse_success_rate,
                "schema_version": schema_version,
                "rule_catalog_version": rule_catalog_version,
                "correlation_version": (
                    correlation_result.version if correlation_result is not None else None
                ),
                "correlation_metrics": (
                    correlation_result.metrics if correlation_result is not None else {}
                ),
            },
        )
        self.database_session.flush()
        return PersistedAnalysisResult(
            session_uuid=analysis_session.session_uuid,
            event_count=len(event_models),
            alert_count=len(alert_models),
            incident_count=len(incident_models),
            file_sha256=file_sha256,
            analysis_fingerprint=fingerprint,
            quarantined_count=analysis_session.total_quarantined,
            parse_success_rate=analysis_session.parse_success_rate,
        )

    def list_analysis_history(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {
                "session_uuid": item.session_uuid,
                "name": item.name,
                "status": item.status,
                "source_type": item.source_type,
                "connector_id": item.connector_id,
                "schema_version": item.schema_version,
                "rule_catalog_version": item.rule_catalog_version,
                "filename": item.original_filename,
                "file_sha256": item.file_sha256,
                "analysis_fingerprint": item.analysis_fingerprint,
                "parser_version": item.parser_version,
                "engine_version": item.engine_version,
                "events": item.total_events,
                "alerts": item.total_alerts,
                "incidents": item.total_incidents,
                "quarantined": item.total_quarantined,
                "parse_success_rate": item.parse_success_rate,
                "started_at": item.started_at,
                "completed_at": item.completed_at,
                "created_at": item.created_at,
            }
            for item in self.analysis_repository.list_recent(limit=limit)
        ]

    def get_analysis_details(self, session_uuid: str) -> dict[str, Any] | None:
        session = self.analysis_repository.get_with_details(session_uuid)
        if session is None:
            return None
        events = sorted(session.events, key=lambda item: item.timestamp or datetime.min)
        alerts = sorted(session.alerts, key=lambda item: item.timestamp or datetime.min)
        incidents = sorted(session.incidents, key=lambda item: item.created_at)
        return {
            "session": {
                "session_uuid": session.session_uuid,
                "name": session.name,
                "status": session.status,
                "source_type": session.source_type,
                "connector_id": session.connector_id,
                "schema_version": session.schema_version,
                "rule_catalog_version": session.rule_catalog_version,
                "filename": session.original_filename,
                "file_sha256": session.file_sha256,
                "analysis_fingerprint": session.analysis_fingerprint,
                "analysis_context": session.analysis_context_json,
                "parser_version": session.parser_version,
                "engine_version": session.engine_version,
                "events": session.total_events,
                "alerts": session.total_alerts,
                "incidents": session.total_incidents,
                "quarantined": session.total_quarantined,
                "parse_success_rate": session.parse_success_rate,
                "parser_statistics": session.parser_statistics_json,
                "started_at": session.started_at,
                "completed_at": session.completed_at,
            },
            "events": [self._event_record(item) for item in events],
            "alerts": [self._alert_record(item) for item in alerts],
            "incidents": [self._incident_record(item) for item in incidents],
            "correlation": self._correlation_record(session, incidents),
        }

    @staticmethod
    def _correlation_record(
        session: AnalysisSessionModel,
        incidents: list[IncidentModel],
    ) -> dict[str, Any] | None:
        if not session.correlation_runs:
            return None
        run = max(session.correlation_runs, key=lambda item: item.created_at)
        metrics = dict(run.metrics_json or {})
        deduplicated_alerts = list(metrics.pop("deduplicated_alerts_detail", []))
        graph = run.graph_snapshot.graph_json if run.graph_snapshot is not None else {}
        incident_uuid_by_id = {item.id: item.incident_uuid for item in incidents}
        return {
            "version": run.algorithm_version,
            "correlation_uuid": run.correlation_uuid,
            "policy": dict(run.policy_json or {}),
            "metrics": metrics,
            "deduplicated_alerts": deduplicated_alerts,
            "incidents": [
                ThreatLensPersistenceService._incident_record(item) for item in incidents
            ],
            "entities": [
                {
                    "entity_uuid": item.entity_uuid,
                    "entity_key": item.entity_key,
                    "entity_type": item.entity_type,
                    "canonical_value": item.canonical_value,
                    "display_value": item.display_value,
                    "confidence": item.confidence,
                    "aliases": item.aliases_json,
                    "source_datasets": item.source_datasets_json,
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "evidence_alert_ids": item.evidence_alert_ids_json,
                    "evidence_event_ids": item.evidence_event_ids_json,
                    "incident_ids": [
                        incident_uuid_by_id.get(incident.id, incident.incident_uuid)
                        for incident in item.incidents
                    ],
                }
                for item in run.entities
            ],
            "relationships": [
                {
                    "relationship_uuid": item.relationship_uuid,
                    "source_node_key": item.source_node_key,
                    "target_node_key": item.target_node_key,
                    "source_alert_id": int(item.source_node_key.split(":")[-1]),
                    "target_alert_id": int(item.target_node_key.split(":")[-1]),
                    "relationship_type": item.relationship_type,
                    "confidence": item.confidence,
                    "shared_entity_count": item.shared_entity_count,
                    "cluster_eligible": item.cluster_eligible,
                    "reasons": item.reasons_json,
                    "shared_entities": item.shared_entities_json,
                    "time_delta_seconds": item.time_delta_seconds,
                    "incident_ids": (
                        [item.incident.incident_uuid] if item.incident is not None else []
                    ),
                }
                for item in run.relationships
            ],
            "graph": graph,
            "graph_sha256": (
                run.graph_snapshot.graph_sha256 if run.graph_snapshot is not None else None
            ),
        }

    @staticmethod
    def _event_record(item: EventModel) -> dict[str, Any]:
        attributes = dict(item.attributes_json or {})
        return {
            "event_uuid": item.event_uuid,
            "event_id": item.external_event_id,
            "schema_version": item.schema_version,
            "timestamp": item.timestamp,
            "original_timestamp": item.original_timestamp,
            "timezone": item.timezone,
            "source_type": item.source_type,
            "source_category": item.source_category,
            "source_product": item.source_product,
            "source_service": item.source_service,
            "source_dataset": item.source_dataset,
            "connector_id": item.source_dataset,
            "ingest_source": attributes.get("filename"),
            "process_name": item.process_name,
            "process_id": item.process_id,
            "parent_process_name": item.parent_process_name,
            "command_line": item.command_line,
            "source_ip": item.source_ip,
            "source_port": item.source_port,
            "destination_ip": item.destination_ip,
            "destination_port": item.destination_port,
            "username": item.username,
            "hostname": item.hostname,
            "event_type": item.event_type,
            "event_action": item.event_action,
            "event_outcome": item.event_outcome,
            "file_path": item.file_path,
            "domain": item.domain,
            "url": item.url,
            "parser_name": item.parser_name,
            "parser_version": item.parser_version,
            "parse_status": item.parse_status,
            "data_quality": item.data_quality_json,
            "attributes": attributes,
            "raw_message": item.raw_message,
            "normalized_message": item.normalized_message,
        }

    @staticmethod
    def _alert_record(item: AlertModel) -> dict[str, Any]:
        mapping = item.attack_mappings_json[0] if item.attack_mappings_json else {}
        return {
            "alert_uuid": item.alert_uuid,
            "rule_id": item.rule_id,
            "rule_title": item.rule_title,
            "rule_status": item.rule_status,
            "timestamp": item.timestamp,
            "source_ip": item.source_ip,
            "username": item.username,
            "hostname": item.hostname,
            "detection_name": item.detection_name,
            "detection_version": item.detection_version,
            "severity": item.severity,
            "confidence": item.confidence,
            "description": item.description,
            "mitre_tactic": item.primary_tactic,
            "mitre_technique": mapping.get("technique"),
            "mitre_technique_id": item.primary_technique_id,
            "attack_mappings": item.attack_mappings_json,
            "recommendation": item.recommendation,
            "playbook": item.playbook,
            "risk_score": item.risk_score,
            "risk_factors": item.risk_factors_json,
            "risk_policy_version": item.risk_policy_version,
            "event_count": item.event_count,
            "supporting_event_uuids": [event.event_uuid for event in item.evidence_events],
        }

    @staticmethod
    def _incident_record(item: IncidentModel) -> dict[str, Any]:
        return {
            "incident_uuid": item.incident_uuid,
            "incident_name": item.title,
            "source_ip": item.source_ip,
            "severity": item.severity,
            "risk_score": item.risk_score,
            "confidence": item.confidence,
            "priority": item.priority,
            "status": item.status,
            "assignee": item.assignee,
            "summary": item.summary,
            "correlation_id": item.correlation_id,
            "correlation_version": item.correlation_version,
            "representative_alert_count": item.representative_alert_count,
            "deduplicated_alert_count": item.deduplicated_alert_count,
            "source_count": item.source_count,
            "entity_count": item.entity_count,
            "relationship_count": item.relationship_count,
            "stage_count": item.stage_count,
            "stage_progression": item.stage_progression,
            "graph_score": item.graph_score,
            "storyline": item.storyline,
            "correlation_metadata": item.correlation_metadata_json,
            "start_time": item.start_time,
            "end_time": item.end_time,
            "alert_count": len(item.alerts),
            "alert_uuids": [alert.alert_uuid for alert in item.alerts],
        }

    def list_incident_cases(
        self,
        status: str | None = None,
        limit: int = 250,
    ) -> list[dict[str, Any]]:
        return [
            {
                "incident_uuid": item.incident_uuid,
                "analysis_session_uuid": item.analysis_session.session_uuid,
                "title": item.title,
                "severity": item.severity,
                "risk_score": item.risk_score,
                "confidence": item.confidence,
                "priority": item.priority,
                "status": item.status,
                "assignee": item.assignee,
                "source_ip": item.source_ip,
                "alert_count": len(item.alerts),
                "source_count": item.source_count,
                "entity_count": item.entity_count,
                "relationship_count": item.relationship_count,
                "stage_count": item.stage_count,
                "stage_progression": item.stage_progression,
                "graph_score": item.graph_score,
                "note_count": len(item.notes),
                "evidence_count": len(item.evidence),
                "created_at": item.created_at,
                "updated_at": item.updated_at,
            }
            for item in self.incident_repository.list_all(status=status, limit=limit)
        ]

    def get_incident_details(self, incident_uuid: str) -> dict[str, Any] | None:
        incident = self.incident_repository.get_by_uuid(incident_uuid)
        if incident is None:
            return None
        audit_records = self.audit_repository.list_recent(
            entity_type="incident", entity_id=incident_uuid, limit=250
        )
        evidence_actor_by_uuid: dict[str, str] = {}
        for record in audit_records:
            if record.action != "incident.evidence_registered":
                continue
            evidence_uuid = str((record.details_json or {}).get("evidence_uuid") or "").strip()
            if evidence_uuid and evidence_uuid not in evidence_actor_by_uuid:
                evidence_actor_by_uuid[evidence_uuid] = record.actor
        alert_records = []
        event_records: dict[str, dict[str, Any]] = {}
        for alert in incident.alerts:
            record = self._alert_record(alert)
            alert_records.append(record)
            for event in alert.evidence_events:
                event_records[event.event_uuid] = self._event_record(event)
        return {
            "incident": self._incident_record(incident),
            "analysis_session_uuid": incident.analysis_session.session_uuid,
            "alerts": alert_records,
            "events": list(event_records.values()),
            "notes": [
                {
                    "id": note.id,
                    "author": note.author,
                    "note": note.note,
                    "created_at": note.created_at,
                }
                for note in sorted(incident.notes, key=lambda item: item.created_at)
            ],
            "evidence": [
                {
                    "evidence_uuid": evidence.evidence_uuid,
                    "evidence_type": evidence.evidence_type,
                    "source_reference": evidence.source_reference,
                    "description": evidence.description,
                    "sha256": evidence.sha256,
                    "registered_by": evidence_actor_by_uuid.get(evidence.evidence_uuid),
                    "created_at": evidence.created_at,
                }
                for evidence in sorted(incident.evidence, key=lambda item: item.created_at)
            ],
            "correlation_entities": [
                {
                    "entity_uuid": entity.entity_uuid,
                    "entity_key": entity.entity_key,
                    "entity_type": entity.entity_type,
                    "canonical_value": entity.canonical_value,
                    "display_value": entity.display_value,
                    "confidence": entity.confidence,
                    "aliases": entity.aliases_json,
                    "source_datasets": entity.source_datasets_json,
                    "evidence_alert_ids": entity.evidence_alert_ids_json,
                    "evidence_event_ids": entity.evidence_event_ids_json,
                    "first_seen": entity.first_seen,
                    "last_seen": entity.last_seen,
                }
                for entity in sorted(
                    incident.correlation_entities,
                    key=lambda item: (item.entity_type, item.canonical_value),
                )
            ],
            "correlation_relationships": [
                {
                    "relationship_uuid": relationship.relationship_uuid,
                    "source_node_key": relationship.source_node_key,
                    "target_node_key": relationship.target_node_key,
                    "relationship_type": relationship.relationship_type,
                    "confidence": relationship.confidence,
                    "shared_entity_count": relationship.shared_entity_count,
                    "cluster_eligible": relationship.cluster_eligible,
                    "reasons": relationship.reasons_json,
                    "shared_entities": relationship.shared_entities_json,
                    "evidence_alert_ids": relationship.evidence_alert_ids_json,
                    "time_delta_seconds": relationship.time_delta_seconds,
                }
                for relationship in sorted(
                    incident.correlation_relationships,
                    key=lambda item: (-item.confidence, item.relationship_uuid),
                )
            ],
            "audit": [
                {
                    "actor": record.actor,
                    "action": record.action,
                    "entity_type": record.entity_type,
                    "entity_id": record.entity_id,
                    "details": record.details_json,
                    "created_at": record.created_at,
                }
                for record in audit_records
            ],
        }

    def update_incident_workflow(
        self,
        *,
        incident_uuid: str,
        status: str,
        assignee: str | None,
        priority: str | None = None,
        actor: str,
    ) -> None:
        normalized_status = status.strip().lower()
        if normalized_status not in VALID_INCIDENT_STATUSES:
            raise InvalidIncidentStateError(f"Unsupported incident status: {status}")
        if priority is not None and priority not in VALID_PRIORITIES:
            raise InvalidIncidentStateError(f"Unsupported incident priority: {priority}")
        incident = self.incident_repository.get_by_uuid(incident_uuid)
        if incident is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_uuid}")
        allowed = ALLOWED_STATUS_TRANSITIONS.get(incident.status, set())
        if normalized_status not in allowed:
            raise InvalidIncidentStateError(
                f"Transition {incident.status} -> {normalized_status} is not allowed."
            )
        before = {
            "status": incident.status,
            "assignee": incident.assignee,
            "priority": incident.priority,
        }
        after = {
            "status": normalized_status,
            "assignee": _clean_text(assignee),
            "priority": priority if priority is not None else incident.priority,
        }
        if after == before:
            return

        incident.status = after["status"]
        incident.assignee = after["assignee"]
        incident.priority = after["priority"]
        incident.updated_at = utc_now()
        self._write_audit_log(
            actor=actor,
            action="incident.workflow_updated",
            entity_type="incident",
            entity_id=incident_uuid,
            details={"before": before, "after": after},
        )

    def add_investigation_note(
        self,
        *,
        incident_uuid: str,
        author: str,
        note: str,
    ) -> str:
        incident = self.incident_repository.get_by_uuid(incident_uuid)
        if incident is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_uuid}")
        cleaned_note = note.strip()
        if not cleaned_note:
            raise ValueError("Investigation note cannot be empty.")
        record = InvestigationNoteModel(
            incident_id=incident.id,
            author=author.strip() or "unknown",
            note=cleaned_note,
        )
        self.database_session.add(record)
        self.database_session.flush()
        self._write_audit_log(
            actor=author,
            action="incident.note_added",
            entity_type="incident",
            entity_id=incident_uuid,
            details={"note_id": record.id},
        )
        return str(record.id)

    def register_evidence(
        self,
        *,
        incident_uuid: str,
        evidence_type: str,
        description: str,
        source_reference: str | None,
        sha256: str | None,
        actor: str,
    ) -> str:
        incident = self.incident_repository.get_by_uuid(incident_uuid)
        if incident is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_uuid}")
        cleaned_type = evidence_type.strip()
        cleaned_description = description.strip()
        cleaned_sha256 = _clean_text(sha256)
        if not cleaned_type or not cleaned_description:
            raise ValueError("Evidence type and description are required.")
        if cleaned_sha256 and not SHA256_PATTERN.fullmatch(cleaned_sha256):
            raise ValueError("Evidence SHA-256 must contain exactly 64 hexadecimal characters.")
        evidence_uuid = str(uuid4())
        self.database_session.add(
            EvidenceModel(
                evidence_uuid=evidence_uuid,
                incident_id=incident.id,
                evidence_type=cleaned_type,
                source_reference=_clean_text(source_reference),
                description=cleaned_description,
                sha256=cleaned_sha256.lower() if cleaned_sha256 else None,
            )
        )
        self._write_audit_log(
            actor=actor,
            action="incident.evidence_registered",
            entity_type="incident",
            entity_id=incident_uuid,
            details={
                "evidence_uuid": evidence_uuid,
                "evidence_type": cleaned_type,
                "sha256": cleaned_sha256,
            },
        )
        return evidence_uuid

    def list_audit_logs(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return [
            {
                "actor": item.actor,
                "action": item.action,
                "entity_type": item.entity_type,
                "entity_id": item.entity_id,
                "details": item.details_json,
                "created_at": item.created_at,
            }
            for item in self.audit_repository.list_recent(
                entity_type=entity_type,
                entity_id=entity_id,
                limit=limit,
            )
        ]
