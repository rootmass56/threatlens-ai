from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.application_service import ThreatLensApplicationService
from database.models import (
    AlertModel,
    AnalysisSessionModel,
    CorrelationEntityModel,
    CorrelationRelationshipModel,
    DetectionFeedbackModel,
    DetectionTuningModel,
    EventModel,
    EvidenceCustodyEventModel,
    EvidenceModel,
    HuntExecutionModel,
    IncidentCaseProfileModel,
    IncidentHandoffModel,
    IncidentModel,
    IncidentTaskModel,
    IngestionSourceModel,
    RealtimeIngressEventModel,
    ResponseExecutionModel,
    ResponsePlaybookModel,
    SavedHuntModel,
    ThreatIndicatorModel,
    ThreatIntelFeedModel,
    ThreatIntelHitModel,
    incident_alerts,
    incident_entities,
    utc_now,
)
from database.service import ThreatLensPersistenceService
from advanced_soc.schemas import (
    CaseProfileUpdate,
    CustodyEventCreate,
    DetectionFeedbackCreate,
    DetectionTuningCreate,
    DetectionTuningReview,
    GraphPathRequest,
    HandoffCreate,
    HuntQuery,
    IncidentTaskCreate,
    IncidentTaskUpdate,
    IngestionSourceCreate,
    IngestionSourceUpdate,
    PlaybookApprovalRequest,
    PlaybookCreate,
    PlaybookExecutionComplete,
    PlaybookExecutionRequest,
    RealtimeIngestRequest,
    SavedHuntCreate,
    ThreatFeedCreate,
    ThreatIndicatorInput,
    ThreatIntelImportRequest,
)


STIX_PATTERN = re.compile(
    r"\[\s*(?P<object>[a-z0-9_-]+):(?P<field>[^=]+?)\s*=\s*['\"](?P<value>.+?)['\"]\s*\]",
    re.IGNORECASE,
)


DEFAULT_PLAYBOOKS: tuple[dict[str, Any], ...] = (
    {
        "name": "Identity Session Containment",
        "description": "Approval-gated identity containment checklist. Execution remains simulated/integration-ready.",
        "action_type": "identity_containment",
        "risk_level": "high",
        "steps": [
            {"order": 1, "action": "validate_identity_evidence", "mode": "manual"},
            {"order": 2, "action": "revoke_active_sessions", "mode": "integration_ready"},
            {"order": 3, "action": "reset_credentials", "mode": "integration_ready"},
            {"order": 4, "action": "verify_recovery", "mode": "manual"},
        ],
    },
    {
        "name": "Endpoint Isolation",
        "description": "Approval-gated endpoint isolation workflow with evidence preservation and rollback notes.",
        "action_type": "endpoint_isolation",
        "risk_level": "critical",
        "steps": [
            {"order": 1, "action": "capture_volatile_context", "mode": "manual"},
            {"order": 2, "action": "isolate_endpoint", "mode": "integration_ready"},
            {"order": 3, "action": "collect_forensic_artifacts", "mode": "integration_ready"},
            {"order": 4, "action": "document_rollback_conditions", "mode": "manual"},
        ],
    },
    {
        "name": "Network Indicator Block",
        "description": "Approval-gated firewall/proxy block request for a verified malicious IOC.",
        "action_type": "network_indicator_block",
        "risk_level": "high",
        "steps": [
            {"order": 1, "action": "validate_ioc_provenance", "mode": "manual"},
            {"order": 2, "action": "scope_affected_assets", "mode": "manual"},
            {"order": 3, "action": "block_indicator", "mode": "integration_ready"},
            {"order": 4, "action": "monitor_false_positive_impact", "mode": "manual"},
        ],
    },
)


def _sha256(value: str | bytes) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _normalize_indicator(indicator_type: str, value: str) -> str:
    kind = indicator_type.lower().strip()
    raw = value.strip()
    if kind in {"ipv4", "ipv6"}:
        return str(ipaddress.ip_address(raw))
    if kind == "domain":
        return raw.lower().rstrip(".")
    if kind == "url":
        parts = urlsplit(raw.strip())
        host = (parts.hostname or "").lower()
        netloc = host
        if parts.port:
            netloc = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, ""))
    if kind in {"sha256", "sha1", "md5"}:
        return raw.lower()
    if kind == "email":
        return raw.lower()
    return raw.lower()


def _stix_indicator(item: dict[str, Any], default_confidence: int, default_tlp: str) -> ThreatIndicatorInput | None:
    if item.get("type") != "indicator" or item.get("revoked") is True:
        return None
    pattern = str(item.get("pattern") or "")
    match = STIX_PATTERN.search(pattern)
    if not match:
        return None
    object_type = match.group("object").lower()
    field = match.group("field").strip().lower().replace(" ", "")
    value = match.group("value")
    mapped: str | None = None
    if object_type == "ipv4-addr" and field == "value":
        mapped = "ipv4"
    elif object_type == "ipv6-addr" and field == "value":
        mapped = "ipv6"
    elif object_type == "domain-name" and field == "value":
        mapped = "domain"
    elif object_type == "url" and field == "value":
        mapped = "url"
    elif object_type == "email-addr" and field == "value":
        mapped = "email"
    elif object_type == "file" and "sha-256" in field:
        mapped = "sha256"
    elif object_type == "file" and "sha-1" in field:
        mapped = "sha1"
    elif object_type == "file" and "md5" in field:
        mapped = "md5"
    if mapped is None:
        return None
    labels = [str(x) for x in item.get("labels") or []][:100]
    return ThreatIndicatorInput(
        indicator_type=mapped,  # type: ignore[arg-type]
        value=value,
        external_id=str(item.get("id") or "") or None,
        confidence=int(item.get("confidence") if item.get("confidence") is not None else default_confidence),
        tlp=default_tlp,
        malicious_score=min(max((int(item.get("confidence") or default_confidence) / 100.0), 0.0), 1.0),
        tags=labels,
        source_reference=str(item.get("external_references") or "")[:2048] or None,
        valid_from=_dt(item.get("valid_from")),
        valid_until=_dt(item.get("valid_until")),
        revoked=bool(item.get("revoked", False)),
    )


class AdvancedSocService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.persistence = ThreatLensPersistenceService(session)

    def audit(self, actor: str, action: str, entity_type: str, entity_id: str, details: dict[str, Any] | None = None) -> None:
        self.persistence.record_audit_event(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details or {},
        )

    # ------------------------------------------------------------------
    # 6A - Real-time authenticated ingestion
    # ------------------------------------------------------------------
    def create_ingestion_source(self, payload: IngestionSourceCreate, actor: str) -> dict[str, Any]:
        from core.connectors import build_default_connector_registry

        build_default_connector_registry().get(payload.connector_id)
        for cidr in payload.allowed_ip_cidrs:
            ipaddress.ip_network(cidr, strict=False)
        secret = "tl_ing_" + secrets.token_urlsafe(32)
        row = IngestionSourceModel(
            source_uuid=str(uuid4()),
            name=payload.name.strip(),
            connector_id=payload.connector_id,
            api_key_hash=_sha256(secret),
            enabled=True,
            rate_limit_per_minute=payload.rate_limit_per_minute,
            allowed_ip_cidrs_json=list(payload.allowed_ip_cidrs),
            metadata_json=dict(payload.metadata),
            created_by=actor,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "ingestion.source_created", "ingestion_source", row.source_uuid, {"connector_id": row.connector_id})
        result = self.serialize_ingestion_source(row)
        result["api_key"] = secret
        result["credential_notice"] = "This machine API key is shown once. Store it outside the repository."
        return result

    @staticmethod
    def serialize_ingestion_source(row: IngestionSourceModel) -> dict[str, Any]:
        return {
            "source_uuid": row.source_uuid,
            "name": row.name,
            "connector_id": row.connector_id,
            "enabled": row.enabled,
            "rate_limit_per_minute": row.rate_limit_per_minute,
            "allowed_ip_cidrs": row.allowed_ip_cidrs_json or [],
            "metadata": row.metadata_json or {},
            "created_by": row.created_by,
            "last_seen_at": row.last_seen_at,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def list_ingestion_sources(self) -> list[dict[str, Any]]:
        rows = self.session.scalars(select(IngestionSourceModel).order_by(IngestionSourceModel.created_at.desc())).all()
        return [self.serialize_ingestion_source(row) for row in rows]

    def update_ingestion_source(self, source_uuid: str, payload: IngestionSourceUpdate, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(IngestionSourceModel).where(IngestionSourceModel.source_uuid == source_uuid))
        if row is None:
            raise LookupError("Ingestion source was not found.")
        values = payload.model_dump(exclude_unset=True)
        if "allowed_ip_cidrs" in values and values["allowed_ip_cidrs"] is not None:
            for cidr in values["allowed_ip_cidrs"]:
                ipaddress.ip_network(cidr, strict=False)
            row.allowed_ip_cidrs_json = list(values.pop("allowed_ip_cidrs"))
        if "metadata" in values:
            row.metadata_json = dict(values.pop("metadata") or {})
        for field, value in values.items():
            setattr(row, field, value)
        self.audit(actor, "ingestion.source_updated", "ingestion_source", source_uuid, {"fields": sorted(payload.model_fields_set)})
        return self.serialize_ingestion_source(row)

    def rotate_ingestion_key(self, source_uuid: str, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(IngestionSourceModel).where(IngestionSourceModel.source_uuid == source_uuid))
        if row is None:
            raise LookupError("Ingestion source was not found.")
        secret = "tl_ing_" + secrets.token_urlsafe(32)
        row.api_key_hash = _sha256(secret)
        self.audit(actor, "ingestion.credential_rotated", "ingestion_source", source_uuid)
        return {"source_uuid": source_uuid, "api_key": secret, "credential_notice": "Previous machine key is invalid immediately."}

    def authenticate_ingestion_source(self, api_key: str, source_ip: str | None = None) -> IngestionSourceModel:
        digest = _sha256(api_key)
        row = self.session.scalar(select(IngestionSourceModel).where(IngestionSourceModel.api_key_hash == digest))
        if row is None or not row.enabled or not hmac.compare_digest(row.api_key_hash, digest):
            raise PermissionError("Invalid or disabled ingestion credential.")
        if source_ip and row.allowed_ip_cidrs_json:
            ip = ipaddress.ip_address(source_ip)
            if not any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in row.allowed_ip_cidrs_json):
                raise PermissionError("Ingestion source IP is outside the configured network allowlist.")
        return row

    def accept_realtime(self, source: IngestionSourceModel, payload: RealtimeIngestRequest, source_ip: str | None) -> dict[str, Any]:
        minute_ago = _now() - timedelta(minutes=1)
        current = int(
            self.session.scalar(
                select(func.count(RealtimeIngressEventModel.id)).where(
                    RealtimeIngressEventModel.source_id == source.id,
                    RealtimeIngressEventModel.received_at >= minute_ago,
                )
            )
            or 0
        )
        if current + len(payload.records) > source.rate_limit_per_minute:
            raise RuntimeError("realtime_ingestion_rate_limit")

        accepted: list[RealtimeIngressEventModel] = []
        duplicates: list[str] = []
        for record in payload.records:
            client_id = record.client_event_id
            if client_id:
                existing = self.session.scalar(
                    select(RealtimeIngressEventModel).where(
                        RealtimeIngressEventModel.source_id == source.id,
                        RealtimeIngressEventModel.client_event_id == client_id,
                    )
                )
                if existing is not None:
                    duplicates.append(client_id)
                    continue
            raw = json.dumps(record.payload, sort_keys=True, separators=(",", ":"), default=str)
            row = RealtimeIngressEventModel(
                ingress_uuid=str(uuid4()),
                source_id=source.id,
                client_event_id=client_id,
                payload_sha256=_sha256(raw),
                status="accepted",
                payload_json=dict(record.payload),
                raw_record=raw,
            )
            self.session.add(row)
            accepted.append(row)
        source.last_seen_at = _now()
        self.session.flush()
        # The receipt rows are deliberately committed before parsing/detection. A parser failure
        # therefore cannot erase evidence that ThreatLens received the telemetry.
        self.session.commit()

        if not accepted:
            return {"accepted": 0, "duplicates": duplicates, "analysis_session_uuid": None, "status": "duplicate_only"}

        jsonl = "\n".join(row.raw_record for row in accepted)
        try:
            result = ThreatLensApplicationService().analyze_and_persist_source(
                analysis_name=payload.analysis_name or f"Realtime {source.name} {utc_now().isoformat()}",
                original_filename=f"realtime-{source.source_uuid}.jsonl",
                raw_content=jsonl,
                connector_id=source.connector_id,
                connector_options=dict(payload.connector_options),
                actor=f"ingestion:{source.source_uuid}",
                allow_duplicate=False,
            )
            analysis_uuid = result.session_uuid
            for row in accepted:
                fresh = self.session.scalar(select(RealtimeIngressEventModel).where(RealtimeIngressEventModel.id == row.id))
                if fresh is not None:
                    fresh.status = "processed"
                    fresh.analysis_session_uuid = analysis_uuid
                    fresh.processed_at = _now()
            self.audit(
                f"ingestion:{source.source_uuid}",
                "ingestion.batch_processed",
                "ingestion_source",
                source.source_uuid,
                {
                    "accepted": len(accepted),
                    "duplicates": len(duplicates),
                    "analysis_session_uuid": analysis_uuid,
                    "source_ip": source_ip,
                    "connector_id": source.connector_id,
                },
            )
            return {
                "accepted": len(accepted),
                "duplicates": duplicates,
                "analysis_session_uuid": analysis_uuid,
                "status": "processed",
                "event_count": result.pipeline.event_count,
                "alert_count": result.pipeline.alert_count,
                "incident_count": result.pipeline.incident_count,
            }
        except Exception as error:
            for row in accepted:
                fresh = self.session.scalar(select(RealtimeIngressEventModel).where(RealtimeIngressEventModel.id == row.id))
                if fresh is not None:
                    fresh.status = "failed"
                    fresh.error_code = type(error).__name__[:128]
                    fresh.error_message = str(error)[:8000]
                    fresh.processed_at = _now()
            self.audit(
                f"ingestion:{source.source_uuid}",
                "ingestion.batch_failed",
                "ingestion_source",
                source.source_uuid,
                {"accepted": len(accepted), "error_type": type(error).__name__},
            )
            raise

    def recent_ingress(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.session.scalars(
            select(RealtimeIngressEventModel).order_by(RealtimeIngressEventModel.received_at.desc()).limit(min(max(limit, 1), 500))
        ).all()
        sources = {row.id: row for row in self.session.scalars(select(IngestionSourceModel)).all()}
        return [
            {
                "ingress_uuid": row.ingress_uuid,
                "source_uuid": sources[row.source_id].source_uuid if row.source_id in sources else None,
                "client_event_id": row.client_event_id,
                "status": row.status,
                "payload_sha256": row.payload_sha256,
                "analysis_session_uuid": row.analysis_session_uuid,
                "error_code": row.error_code,
                "received_at": row.received_at,
                "processed_at": row.processed_at,
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # 6B - Threat intelligence
    # ------------------------------------------------------------------
    def create_feed(self, payload: ThreatFeedCreate, actor: str) -> dict[str, Any]:
        row = ThreatIntelFeedModel(
            feed_uuid=str(uuid4()),
            name=payload.name,
            provider=payload.provider,
            feed_format=payload.feed_format,
            tlp=payload.tlp.upper(),
            default_confidence=payload.default_confidence,
            source_reference=payload.source_reference,
            metadata_json=dict(payload.metadata),
            created_by=actor,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "intel.feed_created", "threat_intel_feed", row.feed_uuid, {"provider": row.provider})
        return self.serialize_feed(row)

    @staticmethod
    def serialize_feed(row: ThreatIntelFeedModel) -> dict[str, Any]:
        return {
            "feed_uuid": row.feed_uuid,
            "name": row.name,
            "provider": row.provider,
            "feed_format": row.feed_format,
            "tlp": row.tlp,
            "default_confidence": row.default_confidence,
            "enabled": row.enabled,
            "source_reference": row.source_reference,
            "metadata": row.metadata_json or {},
            "last_import_at": row.last_import_at,
            "created_at": row.created_at,
        }

    def list_feeds(self) -> list[dict[str, Any]]:
        return [self.serialize_feed(row) for row in self.session.scalars(select(ThreatIntelFeedModel).order_by(ThreatIntelFeedModel.name)).all()]

    def import_indicators(self, feed_uuid: str, payload: ThreatIntelImportRequest, actor: str) -> dict[str, Any]:
        feed = self.session.scalar(select(ThreatIntelFeedModel).where(ThreatIntelFeedModel.feed_uuid == feed_uuid))
        if feed is None:
            raise LookupError("Threat-intelligence feed was not found.")
        inputs = list(payload.indicators)
        if payload.stix_bundle:
            bundle = payload.stix_bundle
            if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
                raise ValueError("stix_bundle must be a STIX 2.x bundle with an objects array.")
            for item in bundle["objects"]:
                if isinstance(item, dict):
                    parsed = _stix_indicator(item, feed.default_confidence, feed.tlp)
                    if parsed is not None:
                        inputs.append(parsed)
        added = 0
        updated = 0
        rejected: list[dict[str, str]] = []
        for item in inputs:
            try:
                normalized = _normalize_indicator(item.indicator_type, item.value)
            except Exception as error:
                rejected.append({"value": item.value[:200], "reason": str(error)})
                continue
            row = self.session.scalar(
                select(ThreatIndicatorModel).where(
                    ThreatIndicatorModel.feed_id == feed.id,
                    ThreatIndicatorModel.indicator_type == item.indicator_type,
                    ThreatIndicatorModel.value_normalized == normalized,
                )
            )
            values = {
                "external_id": item.external_id,
                "value": item.value,
                "confidence": item.confidence if item.confidence is not None else feed.default_confidence,
                "tlp": (item.tlp or feed.tlp).upper(),
                "malicious_score": item.malicious_score,
                "tags_json": list(item.tags),
                "source_reference": item.source_reference or feed.source_reference,
                "first_seen_at": item.first_seen_at,
                "last_seen_at": item.last_seen_at,
                "valid_from": item.valid_from,
                "valid_until": item.valid_until,
                "revoked": item.revoked,
            }
            if row is None:
                row = ThreatIndicatorModel(
                    indicator_uuid=str(uuid4()),
                    feed_id=feed.id,
                    indicator_type=item.indicator_type,
                    value_normalized=normalized,
                    **values,
                )
                self.session.add(row)
                added += 1
            else:
                for field, value in values.items():
                    setattr(row, field, value)
                updated += 1
        feed.last_import_at = _now()
        self.session.flush()
        self.audit(actor, "intel.feed_imported", "threat_intel_feed", feed_uuid, {"added": added, "updated": updated, "rejected": len(rejected)})
        return {"feed_uuid": feed_uuid, "added": added, "updated": updated, "rejected": rejected, "total_received": len(inputs)}

    def list_indicators(self, *, indicator_type: str | None = None, active_only: bool = True, limit: int = 250) -> list[dict[str, Any]]:
        stmt = select(ThreatIndicatorModel).order_by(ThreatIndicatorModel.created_at.desc())
        if indicator_type:
            stmt = stmt.where(ThreatIndicatorModel.indicator_type == indicator_type)
        if active_only:
            now = _now()
            stmt = stmt.where(
                ThreatIndicatorModel.revoked.is_(False),
                or_(ThreatIndicatorModel.valid_until.is_(None), ThreatIndicatorModel.valid_until >= now),
            )
        rows = self.session.scalars(stmt.limit(min(max(limit, 1), 1000))).all()
        feed_map = {row.id: row for row in self.session.scalars(select(ThreatIntelFeedModel)).all()}
        return [
            {
                "indicator_uuid": row.indicator_uuid,
                "type": row.indicator_type,
                "value": row.value,
                "normalized": row.value_normalized,
                "confidence": row.confidence,
                "malicious_score": row.malicious_score,
                "tlp": row.tlp,
                "tags": row.tags_json or [],
                "feed": feed_map[row.feed_id].name if row.feed_id in feed_map else None,
                "provider": feed_map[row.feed_id].provider if row.feed_id in feed_map else None,
                "source_reference": row.source_reference,
                "valid_until": row.valid_until,
                "revoked": row.revoked,
            }
            for row in rows
        ]

    def enrich_analysis(self, session_uuid: str, actor: str) -> dict[str, Any]:
        analysis = self.session.scalar(select(AnalysisSessionModel).where(AnalysisSessionModel.session_uuid == session_uuid))
        if analysis is None:
            raise LookupError("Analysis session was not found.")
        indicators = self.session.scalars(
            select(ThreatIndicatorModel).where(
                ThreatIndicatorModel.revoked.is_(False),
                or_(ThreatIndicatorModel.valid_until.is_(None), ThreatIndicatorModel.valid_until >= _now()),
            )
        ).all()
        lookup: dict[tuple[str, str], ThreatIndicatorModel] = {}
        for item in indicators:
            lookup[(item.indicator_type, item.value_normalized)] = item
        events = self.session.scalars(select(EventModel).where(EventModel.analysis_session_id == analysis.id)).all()
        alert_by_event: dict[int, AlertModel] = {}
        for alert in self.session.scalars(select(AlertModel).where(AlertModel.analysis_session_id == analysis.id)).all():
            if alert.event_id is not None:
                alert_by_event.setdefault(alert.event_id, alert)
        incident_by_alert: dict[int, int] = {}
        for incident_id, alert_id in self.session.execute(
            select(incident_alerts.c.incident_id, incident_alerts.c.alert_id).join(
                IncidentModel, IncidentModel.id == incident_alerts.c.incident_id
            ).where(IncidentModel.analysis_session_id == analysis.id)
        ).all():
            incident_by_alert.setdefault(alert_id, incident_id)
        matches = 0
        for event in events:
            candidates = {
                "source_ip": ("ipv6" if ":" in (event.source_ip or "") else "ipv4", event.source_ip),
                "destination_ip": ("ipv6" if ":" in (event.destination_ip or "") else "ipv4", event.destination_ip),
                "domain": ("domain", event.domain),
                "url": ("url", event.url),
                "file_sha256": ("sha256", (event.attributes_json or {}).get("sha256")),
                "file_sha1": ("sha1", (event.attributes_json or {}).get("sha1")),
                "file_md5": ("md5", (event.attributes_json or {}).get("md5")),
            }
            for field, (kind, value) in candidates.items():
                if not value:
                    continue
                try:
                    normalized = _normalize_indicator(kind, str(value))
                except Exception:
                    continue
                indicator = lookup.get((kind, normalized))
                if indicator is None:
                    continue
                existing = self.session.scalar(
                    select(ThreatIntelHitModel).where(
                        ThreatIntelHitModel.indicator_id == indicator.id,
                        ThreatIntelHitModel.event_id == event.id,
                        ThreatIntelHitModel.matched_field == field,
                    )
                )
                if existing is not None:
                    continue
                alert = alert_by_event.get(event.id)
                self.session.add(
                    ThreatIntelHitModel(
                        hit_uuid=str(uuid4()),
                        indicator_id=indicator.id,
                        event_id=event.id,
                        alert_id=alert.id if alert else None,
                        incident_id=incident_by_alert.get(alert.id) if alert else None,
                        matched_field=field,
                        matched_value=str(value),
                        confidence=indicator.confidence / 100.0,
                        enrichment_only=True,
                        observed_at=event.timestamp,
                    )
                )
                matches += 1
        self.session.flush()
        self.audit(actor, "intel.analysis_enriched", "analysis", session_uuid, {"matches": matches, "indicator_count": len(indicators)})
        return {"analysis_session_uuid": session_uuid, "indicator_count": len(indicators), "new_hits": matches, "authority": "external_intelligence_enrichment_only"}

    def list_intel_hits(self, *, incident_uuid: str | None = None, limit: int = 250) -> list[dict[str, Any]]:
        stmt = select(ThreatIntelHitModel).order_by(ThreatIntelHitModel.created_at.desc())
        if incident_uuid:
            incident = self._incident(incident_uuid)
            stmt = stmt.where(ThreatIntelHitModel.incident_id == incident.id)
        rows = self.session.scalars(stmt.limit(min(max(limit, 1), 1000))).all()
        indicators = {row.id: row for row in self.session.scalars(select(ThreatIndicatorModel)).all()}
        return [
            {
                "hit_uuid": row.hit_uuid,
                "indicator_uuid": indicators[row.indicator_id].indicator_uuid if row.indicator_id in indicators else None,
                "indicator_type": indicators[row.indicator_id].indicator_type if row.indicator_id in indicators else None,
                "indicator_value": indicators[row.indicator_id].value if row.indicator_id in indicators else None,
                "matched_field": row.matched_field,
                "matched_value": row.matched_value,
                "confidence": row.confidence,
                "event_id": row.event_id,
                "alert_id": row.alert_id,
                "incident_id": row.incident_id,
                "enrichment_only": row.enrichment_only,
                "observed_at": row.observed_at,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # 6C - Threat hunting
    # ------------------------------------------------------------------
    def execute_hunt(self, query: HuntQuery, actor: str, saved_hunt_id: int | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        stmt = select(EventModel)
        filters = {
            EventModel.source_product: query.source_product,
            EventModel.source_service: query.source_service,
            EventModel.event_type: query.event_type,
            EventModel.event_outcome: query.outcome,
            EventModel.username: query.username,
            EventModel.hostname: query.hostname,
            EventModel.source_ip: query.source_ip,
            EventModel.destination_ip: query.destination_ip,
            EventModel.domain: query.domain,
            EventModel.process_name: query.process_name,
        }
        for column, value in filters.items():
            if value:
                stmt = stmt.where(column == value)
        if query.start_time:
            stmt = stmt.where(EventModel.timestamp >= query.start_time)
        if query.end_time:
            stmt = stmt.where(EventModel.timestamp <= query.end_time)
        if query.query:
            needle = f"%{query.query.strip()}%"
            stmt = stmt.where(
                or_(
                    EventModel.normalized_message.ilike(needle),
                    EventModel.username.ilike(needle),
                    EventModel.hostname.ilike(needle),
                    EventModel.domain.ilike(needle),
                    EventModel.process_name.ilike(needle),
                    EventModel.source_ip.ilike(needle),
                    EventModel.destination_ip.ilike(needle),
                )
            )
        order = EventModel.timestamp.asc() if query.sort == "asc" else EventModel.timestamp.desc()
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = int(self.session.scalar(count_stmt) or 0)
        rows = self.session.scalars(stmt.order_by(order).offset(query.offset).limit(query.limit)).all()
        latency = round((time.perf_counter() - started) * 1000.0, 2)
        execution = HuntExecutionModel(
            execution_uuid=str(uuid4()),
            saved_hunt_id=saved_hunt_id,
            actor=actor,
            query_json=query.model_dump(mode="json"),
            result_count=total,
            truncated=(query.offset + len(rows)) < total,
            latency_ms=latency,
        )
        self.session.add(execution)
        self.audit(actor, "hunt.executed", "hunt_execution", execution.execution_uuid, {"result_count": total, "latency_ms": latency})
        return {
            "execution_uuid": execution.execution_uuid,
            "total": total,
            "returned": len(rows),
            "truncated": execution.truncated,
            "latency_ms": latency,
            "items": [self.serialize_event(row) for row in rows],
        }

    @staticmethod
    def serialize_event(row: EventModel) -> dict[str, Any]:
        return {
            "event_uuid": row.event_uuid,
            "timestamp": row.timestamp,
            "source_product": row.source_product,
            "source_service": row.source_service,
            "source_dataset": row.source_dataset,
            "event_type": row.event_type,
            "event_action": row.event_action,
            "event_outcome": row.event_outcome,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "username": row.username,
            "hostname": row.hostname,
            "process_name": row.process_name,
            "domain": row.domain,
            "url": row.url,
            "normalized_message": row.normalized_message,
            "attributes": row.attributes_json or {},
        }

    def save_hunt(self, payload: SavedHuntCreate, actor: str) -> dict[str, Any]:
        row = SavedHuntModel(
            hunt_uuid=str(uuid4()),
            name=payload.name,
            description=payload.description,
            owner=actor,
            query_json=payload.query.model_dump(mode="json"),
            shared=payload.shared,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "hunt.saved", "saved_hunt", row.hunt_uuid, {"shared": row.shared})
        return self.serialize_hunt(row)

    @staticmethod
    def serialize_hunt(row: SavedHuntModel) -> dict[str, Any]:
        return {"hunt_uuid": row.hunt_uuid, "name": row.name, "description": row.description, "owner": row.owner, "query": row.query_json, "shared": row.shared, "created_at": row.created_at, "updated_at": row.updated_at}

    def list_saved_hunts(self, actor: str) -> list[dict[str, Any]]:
        rows = self.session.scalars(
            select(SavedHuntModel).where(or_(SavedHuntModel.owner == actor, SavedHuntModel.shared.is_(True))).order_by(SavedHuntModel.updated_at.desc())
        ).all()
        return [self.serialize_hunt(row) for row in rows]

    # ------------------------------------------------------------------
    # 6D - Case operations
    # ------------------------------------------------------------------
    def _incident(self, incident_uuid: str) -> IncidentModel:
        row = self.session.scalar(select(IncidentModel).where(IncidentModel.incident_uuid == incident_uuid))
        if row is None:
            raise LookupError("Incident was not found.")
        return row

    def get_case_operations(self, incident_uuid: str) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        profile = self.session.scalar(select(IncidentCaseProfileModel).where(IncidentCaseProfileModel.incident_id == incident.id))
        tasks = self.session.scalars(select(IncidentTaskModel).where(IncidentTaskModel.incident_id == incident.id).order_by(IncidentTaskModel.created_at.desc())).all()
        handoffs = self.session.scalars(select(IncidentHandoffModel).where(IncidentHandoffModel.incident_id == incident.id).order_by(IncidentHandoffModel.created_at.desc())).all()
        return {
            "incident_uuid": incident_uuid,
            "profile": self.serialize_case_profile(profile) if profile else {
                "team": None, "sla_due_at": None, "escalation_level": 0, "disposition": None,
                "containment_status": "not_started", "resolution_reason": None, "watchers": [], "tags": []
            },
            "tasks": [self.serialize_task(row) for row in tasks],
            "handoffs": [self.serialize_handoff(row) for row in handoffs],
        }

    @staticmethod
    def serialize_case_profile(row: IncidentCaseProfileModel) -> dict[str, Any]:
        return {"team": row.team, "sla_due_at": row.sla_due_at, "escalation_level": row.escalation_level, "disposition": row.disposition, "containment_status": row.containment_status, "resolution_reason": row.resolution_reason, "watchers": row.watchers_json or [], "tags": row.tags_json or [], "updated_by": row.updated_by, "updated_at": row.updated_at}

    def update_case_profile(self, incident_uuid: str, payload: CaseProfileUpdate, actor: str) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        row = self.session.scalar(select(IncidentCaseProfileModel).where(IncidentCaseProfileModel.incident_id == incident.id))
        if row is None:
            row = IncidentCaseProfileModel(incident_id=incident.id, updated_by=actor)
            self.session.add(row)
        values = payload.model_dump(exclude_unset=True)
        if "watchers" in values:
            row.watchers_json = list(values.pop("watchers") or [])
        if "tags" in values:
            row.tags_json = list(values.pop("tags") or [])
        for field, value in values.items():
            setattr(row, field, value)
        row.updated_by = actor
        self.session.flush()
        self.audit(actor, "case.profile_updated", "incident", incident_uuid, {"fields": sorted(payload.model_fields_set)})
        return self.serialize_case_profile(row)

    def create_task(self, incident_uuid: str, payload: IncidentTaskCreate, actor: str) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        row = IncidentTaskModel(
            task_uuid=str(uuid4()), incident_id=incident.id, task_type=payload.task_type,
            title=payload.title, description=payload.description, priority=payload.priority,
            assignee=payload.assignee, due_at=payload.due_at, approval_required=payload.approval_required,
            created_by=actor,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "case.task_created", "incident_task", row.task_uuid, {"incident_uuid": incident_uuid})
        return self.serialize_task(row)

    @staticmethod
    def serialize_task(row: IncidentTaskModel) -> dict[str, Any]:
        return {"task_uuid": row.task_uuid, "task_type": row.task_type, "title": row.title, "description": row.description, "status": row.status, "priority": row.priority, "assignee": row.assignee, "due_at": row.due_at, "approval_required": row.approval_required, "created_by": row.created_by, "completed_by": row.completed_by, "completed_at": row.completed_at, "created_at": row.created_at, "updated_at": row.updated_at}

    def update_task(self, task_uuid: str, payload: IncidentTaskUpdate, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(IncidentTaskModel).where(IncidentTaskModel.task_uuid == task_uuid))
        if row is None:
            raise LookupError("Incident task was not found.")
        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(row, field, value)
        if payload.status == "completed":
            row.completed_by = actor
            row.completed_at = _now()
        self.audit(actor, "case.task_updated", "incident_task", task_uuid, {"fields": sorted(payload.model_fields_set)})
        return self.serialize_task(row)

    def create_handoff(self, incident_uuid: str, payload: HandoffCreate, actor: str) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        row = IncidentHandoffModel(handoff_uuid=str(uuid4()), incident_id=incident.id, from_actor=actor, to_actor=payload.to_actor, note=payload.note)
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "case.handoff_created", "incident_handoff", row.handoff_uuid, {"to": payload.to_actor})
        return self.serialize_handoff(row)

    @staticmethod
    def serialize_handoff(row: IncidentHandoffModel) -> dict[str, Any]:
        return {"handoff_uuid": row.handoff_uuid, "from_actor": row.from_actor, "to_actor": row.to_actor, "note": row.note, "accepted_at": row.accepted_at, "created_at": row.created_at}

    def accept_handoff(self, handoff_uuid: str, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(IncidentHandoffModel).where(IncidentHandoffModel.handoff_uuid == handoff_uuid))
        if row is None:
            raise LookupError("Incident handoff was not found.")
        if row.to_actor != actor:
            raise PermissionError("Only the target analyst may accept this handoff.")
        row.accepted_at = _now()
        self.audit(actor, "case.handoff_accepted", "incident_handoff", handoff_uuid)
        return self.serialize_handoff(row)

    def add_custody_event(self, evidence_uuid: str, payload: CustodyEventCreate, actor: str) -> dict[str, Any]:
        evidence = self.session.scalar(select(EvidenceModel).where(EvidenceModel.evidence_uuid == evidence_uuid))
        if evidence is None:
            raise LookupError("Evidence item was not found.")
        row = EvidenceCustodyEventModel(
            custody_uuid=str(uuid4()), evidence_id=evidence.id, action=payload.action,
            from_custodian=payload.from_custodian, to_custodian=payload.to_custodian,
            location=payload.location, notes=payload.notes, hash_verified=payload.hash_verified, actor=actor,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "evidence.custody_recorded", "evidence", evidence_uuid, {"action": payload.action, "hash_verified": payload.hash_verified})
        return {"custody_uuid": row.custody_uuid, "evidence_uuid": evidence_uuid, "action": row.action, "from_custodian": row.from_custodian, "to_custodian": row.to_custodian, "location": row.location, "notes": row.notes, "hash_verified": row.hash_verified, "actor": row.actor, "created_at": row.created_at}

    def list_custody(self, evidence_uuid: str) -> list[dict[str, Any]]:
        evidence = self.session.scalar(select(EvidenceModel).where(EvidenceModel.evidence_uuid == evidence_uuid))
        if evidence is None:
            raise LookupError("Evidence item was not found.")
        rows = self.session.scalars(select(EvidenceCustodyEventModel).where(EvidenceCustodyEventModel.evidence_id == evidence.id).order_by(EvidenceCustodyEventModel.created_at.asc())).all()
        return [{"custody_uuid": row.custody_uuid, "action": row.action, "from_custodian": row.from_custodian, "to_custodian": row.to_custodian, "location": row.location, "notes": row.notes, "hash_verified": row.hash_verified, "actor": row.actor, "created_at": row.created_at} for row in rows]

    # ------------------------------------------------------------------
    # 6E - Approval-gated response playbooks
    # ------------------------------------------------------------------
    def ensure_default_playbooks(self) -> None:
        for template in DEFAULT_PLAYBOOKS:
            existing = self.session.scalar(select(ResponsePlaybookModel).where(ResponsePlaybookModel.name == template["name"]))
            if existing is None:
                self.session.add(ResponsePlaybookModel(
                    playbook_uuid=str(uuid4()), name=template["name"], description=template["description"],
                    action_type=template["action_type"], risk_level=template["risk_level"], version="1.0.0",
                    steps_json=list(template["steps"]), enabled=True, created_by="system:batch6",
                ))
        self.session.flush()

    def create_playbook(self, payload: PlaybookCreate, actor: str) -> dict[str, Any]:
        row = ResponsePlaybookModel(playbook_uuid=str(uuid4()), name=payload.name, description=payload.description, action_type=payload.action_type, risk_level=payload.risk_level, version=payload.version, steps_json=list(payload.steps), enabled=payload.enabled, created_by=actor)
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "response.playbook_created", "response_playbook", row.playbook_uuid)
        return self.serialize_playbook(row)

    @staticmethod
    def serialize_playbook(row: ResponsePlaybookModel) -> dict[str, Any]:
        return {"playbook_uuid": row.playbook_uuid, "name": row.name, "description": row.description, "action_type": row.action_type, "risk_level": row.risk_level, "version": row.version, "steps": row.steps_json or [], "enabled": row.enabled, "created_by": row.created_by, "created_at": row.created_at}

    def list_playbooks(self) -> list[dict[str, Any]]:
        self.ensure_default_playbooks()
        rows = self.session.scalars(select(ResponsePlaybookModel).order_by(ResponsePlaybookModel.name)).all()
        return [self.serialize_playbook(row) for row in rows]

    def request_playbook(self, incident_uuid: str, payload: PlaybookExecutionRequest, actor: str) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        playbook = self.session.scalar(select(ResponsePlaybookModel).where(ResponsePlaybookModel.playbook_uuid == payload.playbook_uuid))
        if playbook is None or not playbook.enabled:
            raise LookupError("Response playbook was not found or is disabled.")
        row = ResponseExecutionModel(
            execution_uuid=str(uuid4()), playbook_id=playbook.id, incident_id=incident.id,
            status="requested", requested_by=actor, approval_required=True,
            parameters_json=dict(payload.parameters), result_json={},
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "response.execution_requested", "response_execution", row.execution_uuid, {"incident_uuid": incident_uuid, "playbook_uuid": playbook.playbook_uuid})
        return self.serialize_execution(row, playbook)

    @staticmethod
    def serialize_execution(row: ResponseExecutionModel, playbook: ResponsePlaybookModel | None = None) -> dict[str, Any]:
        return {"execution_uuid": row.execution_uuid, "playbook_uuid": playbook.playbook_uuid if playbook else None, "playbook_name": playbook.name if playbook else None, "status": row.status, "requested_by": row.requested_by, "approval_required": row.approval_required, "approved_by": row.approved_by, "approved_at": row.approved_at, "executor": row.executor, "parameters": row.parameters_json or {}, "result": row.result_json or {}, "rollback_notes": row.rollback_notes, "requested_at": row.requested_at, "executed_at": row.executed_at, "completed_at": row.completed_at, "execution_policy": "human_approval_required_no_autonomous_destructive_actions"}

    def approve_execution(self, execution_uuid: str, payload: PlaybookApprovalRequest, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(ResponseExecutionModel).where(ResponseExecutionModel.execution_uuid == execution_uuid))
        if row is None:
            raise LookupError("Response execution was not found.")
        if row.status != "requested":
            raise ValueError("Only a requested response execution can be reviewed.")
        row.approved_by = actor
        row.approved_at = _now()
        if payload.approved:
            row.status = "approved"
        else:
            row.status = "rejected"
            row.completed_at = _now()
            row.result_json = {"review_note": payload.note or "Rejected by approver."}
        self.audit(actor, "response.execution_reviewed", "response_execution", execution_uuid, {"approved": payload.approved, "note": payload.note})
        playbook = self.session.get(ResponsePlaybookModel, row.playbook_id)
        return self.serialize_execution(row, playbook)

    def complete_execution(self, execution_uuid: str, payload: PlaybookExecutionComplete, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(ResponseExecutionModel).where(ResponseExecutionModel.execution_uuid == execution_uuid))
        if row is None:
            raise LookupError("Response execution was not found.")
        if row.status != "approved" or row.approved_at is None:
            raise PermissionError("Response execution requires explicit approval before execution.")
        row.executor = actor
        row.executed_at = _now()
        row.status = "completed" if payload.outcome in {"success", "partial"} else payload.outcome
        row.result_json = {
            "outcome": payload.outcome,
            "mode": "simulation_or_external_integration_record",
            "reported_result": dict(payload.result),
            "safety": "ThreatLens did not perform an autonomous destructive action.",
        }
        row.rollback_notes = payload.rollback_notes
        row.completed_at = _now()
        self.audit(actor, "response.execution_completed", "response_execution", execution_uuid, {"outcome": payload.outcome})
        playbook = self.session.get(ResponsePlaybookModel, row.playbook_id)
        return self.serialize_execution(row, playbook)

    def list_executions(self, incident_uuid: str) -> list[dict[str, Any]]:
        incident = self._incident(incident_uuid)
        rows = self.session.scalars(select(ResponseExecutionModel).where(ResponseExecutionModel.incident_id == incident.id).order_by(ResponseExecutionModel.requested_at.desc())).all()
        playbooks = {row.id: row for row in self.session.scalars(select(ResponsePlaybookModel)).all()}
        return [self.serialize_execution(row, playbooks.get(row.playbook_id)) for row in rows]

    # ------------------------------------------------------------------
    # 6F - Detection feedback and governed tuning
    # ------------------------------------------------------------------
    def create_detection_feedback(self, payload: DetectionFeedbackCreate, actor: str) -> dict[str, Any]:
        alert = self.session.scalar(select(AlertModel).where(AlertModel.alert_uuid == payload.alert_uuid))
        if alert is None:
            raise LookupError("Alert was not found.")
        incident_id = None
        if payload.incident_uuid:
            incident_id = self._incident(payload.incident_uuid).id
        row = DetectionFeedbackModel(
            feedback_uuid=str(uuid4()), alert_id=alert.id, incident_id=incident_id,
            rule_id=alert.rule_id or alert.detection_id, actor=actor, verdict=payload.verdict,
            reason=payload.reason, suppression_scope=payload.suppression_scope,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "detection.feedback_recorded", "detection_feedback", row.feedback_uuid, {"rule_id": row.rule_id, "verdict": row.verdict})
        return self.serialize_feedback(row)

    @staticmethod
    def serialize_feedback(row: DetectionFeedbackModel) -> dict[str, Any]:
        return {"feedback_uuid": row.feedback_uuid, "rule_id": row.rule_id, "verdict": row.verdict, "reason": row.reason, "suppression_scope": row.suppression_scope, "actor": row.actor, "alert_id": row.alert_id, "incident_id": row.incident_id, "created_at": row.created_at}

    def detection_metrics(self) -> list[dict[str, Any]]:
        firing_rows = self.session.execute(
            select(AlertModel.rule_id, AlertModel.detection_id, func.count(AlertModel.id)).group_by(AlertModel.rule_id, AlertModel.detection_id)
        ).all()
        feedback_rows = self.session.execute(
            select(DetectionFeedbackModel.rule_id, DetectionFeedbackModel.verdict, func.count(DetectionFeedbackModel.id)).group_by(DetectionFeedbackModel.rule_id, DetectionFeedbackModel.verdict)
        ).all()
        feedback: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for rule_id, verdict, count in feedback_rows:
            feedback[str(rule_id)][str(verdict)] = int(count)
        results = []
        seen: set[str] = set()
        for rule_id, detection_id, count in firing_rows:
            key = str(rule_id or detection_id)
            if key in seen:
                continue
            seen.add(key)
            f = feedback[key]
            reviewed = sum(f.values())
            tp = f.get("true_positive", 0)
            fp = f.get("false_positive", 0)
            results.append({
                "rule_id": key, "alert_firings": int(count), "reviewed": reviewed,
                "true_positive": tp, "false_positive": fp, "benign": f.get("benign", 0), "unknown": f.get("unknown", 0),
                "precision_observed": round(tp / max(tp + fp, 1), 4) if reviewed else None,
                "feedback_coverage": round(reviewed / max(int(count), 1), 4),
            })
        return sorted(results, key=lambda x: (-x["alert_firings"], x["rule_id"]))

    def propose_tuning(self, payload: DetectionTuningCreate, actor: str) -> dict[str, Any]:
        row = DetectionTuningModel(
            tuning_uuid=str(uuid4()), rule_id=payload.rule_id, rule_version=payload.rule_version,
            proposal_type=payload.proposal_type, proposal_json=dict(payload.proposal), rationale=payload.rationale,
            status="proposed", requested_by=actor, patch_json={},
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "detection.tuning_proposed", "detection_tuning", row.tuning_uuid, {"rule_id": row.rule_id, "proposal_type": row.proposal_type})
        return self.serialize_tuning(row)

    def review_tuning(self, tuning_uuid: str, payload: DetectionTuningReview, actor: str) -> dict[str, Any]:
        row = self.session.scalar(select(DetectionTuningModel).where(DetectionTuningModel.tuning_uuid == tuning_uuid))
        if row is None:
            raise LookupError("Detection tuning proposal was not found.")
        if row.status != "proposed":
            raise ValueError("Only proposed detection tunings may be reviewed.")
        row.status = payload.decision
        row.reviewed_by = actor
        row.reviewed_at = _now()
        if payload.decision == "approved":
            row.patch_json = {
                "schema": "threatlens-governed-rule-patch-1.0",
                "rule_id": row.rule_id,
                "rule_version": row.rule_version,
                "proposal_type": row.proposal_type,
                "change": row.proposal_json,
                "reviewed_by": actor,
                "review_note": payload.review_note,
                "runtime_mutation": False,
                "next_step": "export_patch_then_update_versioned_yaml_and_run_rule_fixtures",
            }
        self.audit(actor, "detection.tuning_reviewed", "detection_tuning", tuning_uuid, {"decision": payload.decision})
        return self.serialize_tuning(row)

    @staticmethod
    def serialize_tuning(row: DetectionTuningModel) -> dict[str, Any]:
        return {"tuning_uuid": row.tuning_uuid, "rule_id": row.rule_id, "rule_version": row.rule_version, "proposal_type": row.proposal_type, "proposal": row.proposal_json or {}, "rationale": row.rationale, "status": row.status, "requested_by": row.requested_by, "reviewed_by": row.reviewed_by, "reviewed_at": row.reviewed_at, "patch": row.patch_json or {}, "created_at": row.created_at, "updated_at": row.updated_at}

    def list_tunings(self) -> list[dict[str, Any]]:
        return [self.serialize_tuning(row) for row in self.session.scalars(select(DetectionTuningModel).order_by(DetectionTuningModel.created_at.desc())).all()]

    # ------------------------------------------------------------------
    # 6H - Graph intelligence and global search
    # ------------------------------------------------------------------
    def graph_intelligence(self, incident_uuid: str, *, minimum_confidence: float = 0.0, entity_type: str | None = None) -> dict[str, Any]:
        incident = self._incident(incident_uuid)
        entity_stmt = select(CorrelationEntityModel).join(
            incident_entities, incident_entities.c.entity_id == CorrelationEntityModel.id
        ).where(incident_entities.c.incident_id == incident.id)
        if entity_type:
            entity_stmt = entity_stmt.where(CorrelationEntityModel.entity_type == entity_type)
        entities = self.session.scalars(entity_stmt.order_by(CorrelationEntityModel.confidence.desc())).all()
        edges = self.session.scalars(
            select(CorrelationRelationshipModel).where(
                CorrelationRelationshipModel.incident_id == incident.id,
                CorrelationRelationshipModel.confidence >= minimum_confidence,
            ).order_by(CorrelationRelationshipModel.confidence.desc())
        ).all()
        return {
            "incident_uuid": incident_uuid,
            "nodes": [
                {"node_key": e.entity_key, "entity_uuid": e.entity_uuid, "type": e.entity_type, "value": e.display_value, "confidence": e.confidence, "aliases": e.aliases_json or [], "sources": e.source_datasets_json or [], "evidence_alert_ids": e.evidence_alert_ids_json or [], "evidence_event_ids": e.evidence_event_ids_json or [], "first_seen": e.first_seen, "last_seen": e.last_seen}
                for e in entities
            ],
            "edges": [
                {"relationship_uuid": e.relationship_uuid, "source": e.source_node_key, "target": e.target_node_key, "type": e.relationship_type, "confidence": e.confidence, "reasons": e.reasons_json or [], "shared_entities": e.shared_entities_json or [], "evidence_alert_ids": e.evidence_alert_ids_json or [], "time_delta_seconds": e.time_delta_seconds}
                for e in edges
            ],
            "summary": {"node_count": len(entities), "edge_count": len(edges), "minimum_confidence": minimum_confidence},
        }

    def graph_path(self, incident_uuid: str, payload: GraphPathRequest) -> dict[str, Any]:
        graph = self.graph_intelligence(incident_uuid, minimum_confidence=payload.minimum_confidence)
        adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        for edge in graph["edges"]:
            adjacency[edge["source"]].append((edge["target"], edge))
            adjacency[edge["target"]].append((edge["source"], edge))
        queue = deque([(payload.source_node_key, [])])
        visited = {payload.source_node_key}
        while queue:
            node, path = queue.popleft()
            if node == payload.target_node_key:
                return {"found": True, "source": payload.source_node_key, "target": payload.target_node_key, "hop_count": len(path), "path": path, "explanation": " -> ".join([payload.source_node_key] + [step["to"] for step in path])}
            for target, edge in adjacency.get(node, []):
                if target in visited:
                    continue
                visited.add(target)
                queue.append((target, [*path, {"from": node, "to": target, "relationship_type": edge["type"], "confidence": edge["confidence"], "reasons": edge["reasons"]}]))
        return {"found": False, "source": payload.source_node_key, "target": payload.target_node_key, "hop_count": 0, "path": [], "explanation": "No evidence-backed path met the requested confidence threshold."}

    def entity_timeline(self, entity_uuid: str, limit: int = 250) -> dict[str, Any]:
        entity = self.session.scalar(select(CorrelationEntityModel).where(CorrelationEntityModel.entity_uuid == entity_uuid))
        if entity is None:
            raise LookupError("Correlation entity was not found.")
        ids = [int(x) for x in (entity.evidence_event_ids_json or []) if str(x).isdigit()]
        if not ids:
            return {"entity_uuid": entity_uuid, "items": [], "count": 0}
        rows = self.session.scalars(select(EventModel).where(EventModel.id.in_(ids)).order_by(EventModel.timestamp.asc()).limit(min(max(limit, 1), 1000))).all()
        return {"entity_uuid": entity_uuid, "entity_type": entity.entity_type, "value": entity.display_value, "items": [self.serialize_event(row) for row in rows], "count": len(rows)}

    def global_search(self, query: str, *, entity_types: list[str], limit: int = 100, offset: int = 0) -> dict[str, Any]:
        needle = f"%{query.strip()}%"
        results: list[dict[str, Any]] = []
        per_type = min(max(limit, 1), 250)
        if "incident" in entity_types:
            for row in self.session.scalars(select(IncidentModel).where(or_(IncidentModel.title.ilike(needle), IncidentModel.summary.ilike(needle), IncidentModel.category.ilike(needle), IncidentModel.source_ip.ilike(needle))).order_by(IncidentModel.updated_at.desc()).limit(per_type)).all():
                results.append({"type": "incident", "id": row.incident_uuid, "title": row.title, "subtitle": f"{row.priority} · {row.status} · risk {row.risk_score}", "timestamp": row.updated_at})
        if "alert" in entity_types:
            for row in self.session.scalars(select(AlertModel).where(or_(AlertModel.detection_name.ilike(needle), AlertModel.description.ilike(needle), AlertModel.source_ip.ilike(needle), AlertModel.username.ilike(needle), AlertModel.hostname.ilike(needle))).order_by(AlertModel.created_at.desc()).limit(per_type)).all():
                results.append({"type": "alert", "id": row.alert_uuid, "title": row.detection_name, "subtitle": f"{row.severity} · risk {row.risk_score}", "timestamp": row.timestamp or row.created_at})
        if "event" in entity_types:
            for row in self.session.scalars(select(EventModel).where(or_(EventModel.normalized_message.ilike(needle), EventModel.username.ilike(needle), EventModel.hostname.ilike(needle), EventModel.domain.ilike(needle), EventModel.source_ip.ilike(needle), EventModel.destination_ip.ilike(needle))).order_by(EventModel.timestamp.desc()).limit(per_type)).all():
                results.append({"type": "event", "id": row.event_uuid, "title": row.event_type, "subtitle": row.normalized_message[:200], "timestamp": row.timestamp or row.created_at})
        if "entity" in entity_types:
            for row in self.session.scalars(select(CorrelationEntityModel).where(or_(CorrelationEntityModel.display_value.ilike(needle), CorrelationEntityModel.canonical_value.ilike(needle), CorrelationEntityModel.entity_key.ilike(needle))).order_by(CorrelationEntityModel.last_seen.desc()).limit(per_type)).all():
                results.append({"type": "entity", "id": row.entity_uuid, "title": row.display_value, "subtitle": f"{row.entity_type} · confidence {row.confidence:.2f}", "timestamp": row.last_seen or row.created_at})
        if "indicator" in entity_types:
            for row in self.session.scalars(select(ThreatIndicatorModel).where(or_(ThreatIndicatorModel.value.ilike(needle), ThreatIndicatorModel.value_normalized.ilike(needle), ThreatIndicatorModel.indicator_type.ilike(needle))).order_by(ThreatIndicatorModel.created_at.desc()).limit(per_type)).all():
                results.append({"type": "indicator", "id": row.indicator_uuid, "title": row.value, "subtitle": f"{row.indicator_type} · confidence {row.confidence} · {row.tlp}", "timestamp": row.created_at})
        results.sort(key=lambda item: item["timestamp"] or datetime.min.replace(tzinfo=UTC), reverse=True)
        total = len(results)
        sliced = results[offset : offset + limit]
        return {"query": query, "total_candidates": total, "returned": len(sliced), "offset": offset, "limit": limit, "items": sliced}
