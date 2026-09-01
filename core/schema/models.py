from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

COMMON_EVENT_SCHEMA_VERSION = "1.0.0"


class ParseStatus(StrEnum):
    """Normalization outcome for one source record."""

    PARSED = "parsed"
    PARTIAL = "partial"
    QUARANTINED = "quarantined"


class DataQualitySeverity(StrEnum):
    """Severity of a parser or normalization quality finding."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DataQualityFinding(BaseModel):
    """Explain why a normalized field is absent, repaired or untrusted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=2, max_length=128)
    severity: DataQualitySeverity
    message: str = Field(min_length=2, max_length=1024)
    field: str | None = Field(default=None, max_length=128)
    raw_value: str | None = Field(default=None, max_length=2048)


class CommonEvent(BaseModel):
    """Versioned vendor-neutral event used by every ThreatLens connector."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: str = Field(default=COMMON_EVENT_SCHEMA_VERSION)
    event_uuid: UUID = Field(default_factory=uuid4)
    external_event_id: str | None = Field(default=None, max_length=128)

    timestamp: datetime | None = None
    original_timestamp: str | None = Field(default=None, max_length=256)
    timezone: str = Field(default="UTC", max_length=64)

    source_category: str = Field(min_length=1, max_length=64)
    source_product: str = Field(min_length=1, max_length=64)
    source_service: str = Field(min_length=1, max_length=64)
    source_dataset: str = Field(min_length=1, max_length=128)

    event_type: str = Field(min_length=1, max_length=128)
    event_action: str | None = Field(default=None, max_length=128)
    event_outcome: str | None = Field(default=None, max_length=64)

    source_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    username: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)

    process_name: str | None = Field(default=None, max_length=512)
    process_id: int | None = Field(default=None, ge=0)
    parent_process_name: str | None = Field(default=None, max_length=512)
    command_line: str | None = Field(default=None, max_length=16384)

    file_path: str | None = Field(default=None, max_length=4096)
    domain: str | None = Field(default=None, max_length=1024)
    url: str | None = Field(default=None, max_length=8192)

    raw_message: str = Field(min_length=1)
    normalized_message: str = Field(min_length=1)

    parser_name: str = Field(min_length=1, max_length=128)
    parser_version: str = Field(min_length=1, max_length=32)
    parse_status: ParseStatus = ParseStatus.PARSED
    data_quality: list[DataQualityFinding] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "external_event_id",
        "original_timestamp",
        "event_action",
        "event_outcome",
        "source_ip",
        "destination_ip",
        "username",
        "hostname",
        "process_name",
        "parent_process_name",
        "command_line",
        "file_path",
        "domain",
        "url",
        mode="before",
    )
    @classmethod
    def normalize_optional_text(cls, value: Any) -> Any:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value))

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_parse_quality(self) -> CommonEvent:
        if self.parse_status == ParseStatus.PARTIAL and not self.data_quality:
            raise ValueError("Partially parsed events require a data-quality finding.")
        return self

    def to_record(self, event_id: int) -> dict[str, Any]:
        """Export a DataFrame/database-compatible flat event record."""

        record = self.model_dump(mode="json")
        record["event_id"] = event_id
        record["event_uuid"] = str(self.event_uuid)
        record["timestamp"] = self.timestamp.isoformat() if self.timestamp else ""
        record["source_type"] = self.source_dataset
        record["data_quality"] = [item.model_dump(mode="json") for item in self.data_quality]
        record["attributes"] = dict(self.attributes)
        return record


class QuarantinedRecord(BaseModel):
    """Source record that could not be normalized safely."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_number: int = Field(ge=1)
    raw_record: str
    reason_code: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=2, max_length=2048)
    parser_name: str = Field(min_length=1, max_length=128)
    parser_version: str = Field(min_length=1, max_length=32)
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ParserStatistics(BaseModel):
    """Quality and volume measurements returned by every connector."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str = Field(min_length=1, max_length=128)
    parser_name: str = Field(min_length=1, max_length=128)
    parser_version: str = Field(min_length=1, max_length=32)
    schema_version: str = COMMON_EVENT_SCHEMA_VERSION
    total_records: int = Field(ge=0)
    parsed_records: int = Field(ge=0)
    partial_records: int = Field(ge=0)
    quarantined_records: int = Field(ge=0)
    empty_records: int = Field(ge=0)
    parse_success_rate: float = Field(ge=0.0, le=1.0)
    quality_findings: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts(self) -> ParserStatistics:
        accounted = (
            self.parsed_records
            + self.partial_records
            + self.quarantined_records
            + self.empty_records
        )
        if accounted != self.total_records:
            raise ValueError(
                "Parser statistics are inconsistent: parsed + partial + quarantined + empty "
                "must equal total_records."
            )
        return self


class SourceValidationResult(BaseModel):
    """Connector validation response before parsing begins."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    confidence: float = Field(ge=0.0, le=1.0)
    connector_id: str
    reasons: list[str] = Field(default_factory=list)


class ParserResult(BaseModel):
    """Complete connector output including events and quarantined records."""

    model_config = ConfigDict(extra="forbid")

    connector_id: str
    events: list[CommonEvent] = Field(default_factory=list)
    quarantined_records: list[QuarantinedRecord] = Field(default_factory=list)
    statistics: ParserStatistics
    source_metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dataframe(self) -> pd.DataFrame:
        records = [event.to_record(index) for index, event in enumerate(self.events, start=1)]
        if records:
            return pd.DataFrame(records)
        return pd.DataFrame(columns=COMMON_EVENT_COLUMNS)

    def quarantined_to_dataframe(self) -> pd.DataFrame:
        records = [record.model_dump(mode="json") for record in self.quarantined_records]
        return pd.DataFrame(records)


COMMON_EVENT_COLUMNS = [
    "event_id",
    "event_uuid",
    "external_event_id",
    "schema_version",
    "timestamp",
    "original_timestamp",
    "timezone",
    "source_type",
    "source_category",
    "source_product",
    "source_service",
    "source_dataset",
    "event_type",
    "event_action",
    "event_outcome",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "username",
    "hostname",
    "process_name",
    "process_id",
    "parent_process_name",
    "command_line",
    "file_path",
    "domain",
    "url",
    "raw_message",
    "normalized_message",
    "parser_name",
    "parser_version",
    "parse_status",
    "data_quality",
    "attributes",
]


SeverityName = Literal["Low", "Medium", "High", "Critical"]
