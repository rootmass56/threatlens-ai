from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IngestionSourceCreate(StrictModel):
    name: str = Field(min_length=2, max_length=255)
    connector_id: str = Field(min_length=2, max_length=128)
    rate_limit_per_minute: int = Field(default=1200, ge=1, le=100_000)
    allowed_ip_cidrs: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestionSourceUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    enabled: bool | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=100_000)
    allowed_ip_cidrs: list[str] | None = Field(default=None, max_length=64)
    metadata: dict[str, Any] | None = None


class RealtimeRecord(StrictModel):
    client_event_id: str | None = Field(default=None, max_length=255)
    payload: dict[str, Any]


class RealtimeIngestRequest(StrictModel):
    records: list[RealtimeRecord] = Field(min_length=1, max_length=500)
    analysis_name: str | None = Field(default=None, max_length=255)
    connector_options: dict[str, Any] = Field(default_factory=dict)


class ThreatFeedCreate(StrictModel):
    name: str = Field(min_length=2, max_length=255)
    provider: str = Field(min_length=2, max_length=255)
    feed_format: Literal["curated_json", "stix2"] = "curated_json"
    tlp: str = Field(default="TLP:CLEAR", max_length=16)
    default_confidence: int = Field(default=70, ge=0, le=100)
    source_reference: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIndicatorInput(StrictModel):
    indicator_type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"]
    value: str = Field(min_length=1, max_length=8192)
    external_id: str | None = Field(default=None, max_length=255)
    confidence: int | None = Field(default=None, ge=0, le=100)
    tlp: str | None = Field(default=None, max_length=16)
    malicious_score: float = Field(default=0.7, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list, max_length=100)
    source_reference: str | None = Field(default=None, max_length=2048)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    revoked: bool = False


class ThreatIntelImportRequest(StrictModel):
    indicators: list[ThreatIndicatorInput] = Field(default_factory=list, max_length=20_000)
    stix_bundle: dict[str, Any] | None = None

    @model_validator(mode="after")
    def require_content(self):
        if not self.indicators and not self.stix_bundle:
            raise ValueError("Provide curated indicators or a STIX 2.x bundle.")
        return self


class HuntQuery(StrictModel):
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_product: str | None = Field(default=None, max_length=64)
    source_service: str | None = Field(default=None, max_length=64)
    event_type: str | None = Field(default=None, max_length=128)
    outcome: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    domain: str | None = Field(default=None, max_length=1024)
    process_name: str | None = Field(default=None, max_length=512)
    query: str | None = Field(default=None, max_length=512)
    limit: int = Field(default=200, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100_000)
    sort: Literal["asc", "desc"] = "desc"

    @model_validator(mode="after")
    def validate_window(self):
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time cannot be later than end_time.")
        return self


class SavedHuntCreate(StrictModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = Field(default="", max_length=4000)
    query: HuntQuery
    shared: bool = False


class CaseProfileUpdate(StrictModel):
    team: str | None = Field(default=None, max_length=255)
    sla_due_at: datetime | None = None
    escalation_level: int | None = Field(default=None, ge=0, le=5)
    disposition: Literal["true_positive", "false_positive", "benign", "duplicate", "inconclusive"] | None = None
    containment_status: Literal["not_started", "planned", "in_progress", "contained", "monitoring", "released"] | None = None
    resolution_reason: str | None = Field(default=None, max_length=8000)
    watchers: list[str] | None = Field(default=None, max_length=100)
    tags: list[str] | None = Field(default=None, max_length=100)


class IncidentTaskCreate(StrictModel):
    task_type: Literal["investigation", "containment", "collection", "communication", "recovery", "review"] = "investigation"
    title: str = Field(min_length=2, max_length=255)
    description: str = Field(default="", max_length=8000)
    priority: Literal["P1", "P2", "P3", "P4"] = "P3"
    assignee: str | None = Field(default=None, max_length=255)
    due_at: datetime | None = None
    approval_required: bool = False


class IncidentTaskUpdate(StrictModel):
    status: Literal["open", "in_progress", "blocked", "completed", "cancelled"] | None = None
    priority: Literal["P1", "P2", "P3", "P4"] | None = None
    assignee: str | None = Field(default=None, max_length=255)
    due_at: datetime | None = None
    description: str | None = Field(default=None, max_length=8000)


class HandoffCreate(StrictModel):
    to_actor: str = Field(min_length=1, max_length=255)
    note: str = Field(min_length=2, max_length=10_000)


class CustodyEventCreate(StrictModel):
    action: Literal["registered", "collected", "transferred", "verified", "stored", "released", "archived"]
    from_custodian: str | None = Field(default=None, max_length=255)
    to_custodian: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=1024)
    notes: str = Field(default="", max_length=8000)
    hash_verified: bool = False


class PlaybookCreate(StrictModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = Field(default="", max_length=8000)
    action_type: str = Field(min_length=2, max_length=128)
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    version: str = Field(default="1.0.0", max_length=32)
    steps: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    enabled: bool = True


class PlaybookExecutionRequest(StrictModel):
    playbook_uuid: str = Field(min_length=36, max_length=36)
    parameters: dict[str, Any] = Field(default_factory=dict)


class PlaybookApprovalRequest(StrictModel):
    approved: bool
    note: str | None = Field(default=None, max_length=4000)


class PlaybookExecutionComplete(StrictModel):
    outcome: Literal["success", "partial", "failed", "cancelled"] = "success"
    result: dict[str, Any] = Field(default_factory=dict)
    rollback_notes: str | None = Field(default=None, max_length=8000)


class DetectionFeedbackCreate(StrictModel):
    alert_uuid: str = Field(min_length=36, max_length=36)
    incident_uuid: str | None = Field(default=None, min_length=36, max_length=36)
    verdict: Literal["true_positive", "false_positive", "benign", "unknown"]
    reason: str = Field(default="", max_length=8000)
    suppression_scope: str | None = Field(default=None, max_length=255)


class DetectionTuningCreate(StrictModel):
    rule_id: str = Field(min_length=1, max_length=128)
    rule_version: str | None = Field(default=None, max_length=32)
    proposal_type: Literal["threshold", "allowlist", "suppression", "condition", "severity", "metadata"]
    proposal: dict[str, Any]
    rationale: str = Field(min_length=2, max_length=10_000)


class DetectionTuningReview(StrictModel):
    decision: Literal["approved", "rejected"]
    review_note: str | None = Field(default=None, max_length=4000)


class GraphPathRequest(StrictModel):
    source_node_key: str = Field(min_length=1, max_length=1024)
    target_node_key: str = Field(min_length=1, max_length=1024)
    minimum_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class GlobalSearchQuery(StrictModel):
    query: str = Field(min_length=2, max_length=512)
    limit: int = Field(default=100, ge=1, le=250)
    offset: int = Field(default=0, ge=0, le=100_000)
    entity_types: list[Literal["incident", "alert", "event", "entity", "indicator"]] = Field(
        default_factory=lambda: ["incident", "alert", "event", "entity", "indicator"]
    )
