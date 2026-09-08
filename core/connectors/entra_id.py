from __future__ import annotations

from collections import Counter
from typing import Any

from pydantic import ValidationError

from core.connectors.base import ConnectorMetadata, SecurityLogConnector
from core.connectors.structured import (
    clean_text,
    get_value,
    load_structured_records,
    parse_timestamp,
    safe_ip,
)
from core.schema import (
    CommonEvent,
    DataQualityFinding,
    DataQualitySeverity,
    ParserResult,
    ParserStatistics,
    ParseStatus,
    QuarantinedRecord,
    SourceValidationResult,
)


class EntraIdConnector(SecurityLogConnector):
    """Normalize Microsoft Entra ID sign-in and audit events."""

    metadata = ConnectorMetadata(
        connector_id="entra_id",
        name="Microsoft Entra ID",
        product="microsoft_entra_id",
        service="identity",
        category="identity",
        parser_version="1.0.0",
        supported_extensions=(".json", ".jsonl", ".ndjson"),
        description="Parses Entra sign-in and audit records into the ThreatLens common event schema.",
    )

    def validate_source(self, raw_content: str | bytes, *, filename: str | None = None) -> SourceValidationResult:
        loaded = load_structured_records(raw_content, filename=filename)
        sample = loaded.records[:30]
        if not sample:
            return SourceValidationResult(valid=False, confidence=0.0, connector_id=self.metadata.connector_id, reasons=["No structured Entra records were available."])
        markers = 0
        for item in sample:
            if any(
                get_value(item.payload, key) is not None
                for key in (
                    "userPrincipalName", "createdDateTime", "conditionalAccessStatus",
                    "riskLevelDuringSignIn", "activityDisplayName", "activityDateTime",
                    "initiatedBy.user.userPrincipalName",
                )
            ):
                markers += 1
        confidence = markers / len(sample)
        if filename and any(word in filename.lower() for word in ("entra", "azure", "signin", "audit")):
            confidence = min(confidence + 0.15, 1.0)
        return SourceValidationResult(
            valid=markers >= max(1, len(sample) // 2),
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=[f"{markers}/{len(sample)} sampled records contain Entra sign-in/audit markers."],
        )

    @staticmethod
    def _classification(record: dict[str, Any]) -> tuple[str, str, str | None, str]:
        activity = (clean_text(get_value(record, "activityDisplayName", "activity")) or "").lower()
        if activity:
            if "role" in activity and any(token in activity for token in ("add", "assign", "eligible", "member")):
                return "entra_privileged_role_assignment", "role_assignment", "success", "privilege"
            return "entra_audit_activity", "audit_activity", "success", "identity"

        error_raw = get_value(record, "status.errorCode", "errorCode", "status.error_code", default=0)
        try:
            error_code = int(error_raw or 0)
        except (TypeError, ValueError):
            error_code = -1
        failure_reason = (clean_text(get_value(record, "status.failureReason", "failureReason")) or "").lower()
        risk = (clean_text(get_value(record, "riskLevelDuringSignIn", "riskLevelAggregated")) or "").lower()
        if "mfa" in failure_reason or "multi-factor" in failure_reason or "multifactor" in failure_reason:
            return "entra_mfa_failure", "authentication", "failure", "authentication"
        if error_code != 0:
            return "entra_signin_failure", "authentication", "failure", "authentication"
        if risk in {"medium", "high", "hidden"}:
            return "entra_risky_signin", "authentication", "success", "authentication"
        return "entra_signin_success", "authentication", "success", "authentication"

    def parse(self, raw_content: str | bytes, *, filename: str | None = None, options: dict[str, Any] | None = None) -> ParserResult:
        del options
        loaded = load_structured_records(raw_content, filename=filename)
        events: list[CommonEvent] = []
        quarantined = [
            QuarantinedRecord(
                record_number=e.record_number, raw_record=e.raw_record,
                reason_code=e.reason_code, reason=e.reason,
                parser_name=self.metadata.connector_id, parser_version=self.metadata.parser_version,
            )
            for e in loaded.errors
        ]
        quality: Counter[str] = Counter(e.reason_code for e in loaded.errors)

        for item in loaded.records:
            timestamp_raw = get_value(item.payload, "createdDateTime", "activityDateTime", "timestamp", "@timestamp")
            timestamp = parse_timestamp(timestamp_raw)
            findings: list[DataQualityFinding] = []
            parse_status = ParseStatus.PARSED
            if timestamp is None:
                findings.append(DataQualityFinding(
                    code="missing_or_invalid_timestamp", severity=DataQualitySeverity.WARNING,
                    field="timestamp", raw_value=clean_text(timestamp_raw),
                    message="The Entra timestamp could not be normalized.",
                ))
                quality["missing_or_invalid_timestamp"] += 1
                parse_status = ParseStatus.PARTIAL

            event_type, action, outcome, category = self._classification(item.payload)
            username = clean_text(get_value(
                item.payload, "userPrincipalName", "userDisplayName",
                "initiatedBy.user.userPrincipalName", "initiatedBy.user.displayName",
            ))
            source_ip = safe_ip(get_value(item.payload, "ipAddress", "initiatedBy.user.ipAddress", "client.ip"))
            hostname = clean_text(get_value(item.payload, "deviceDetail.displayName", "deviceDetail.deviceId", "deviceId"))
            app_name = clean_text(get_value(item.payload, "appDisplayName", "resourceDisplayName", "targetResources.0.displayName"))
            activity = clean_text(get_value(item.payload, "activityDisplayName"))
            failure_reason = clean_text(get_value(item.payload, "status.failureReason", "failureReason"))
            risk = clean_text(get_value(item.payload, "riskLevelDuringSignIn", "riskLevelAggregated"))
            conditional_access = clean_text(get_value(item.payload, "conditionalAccessStatus"))
            country = clean_text(get_value(item.payload, "location.countryOrRegion"))
            city = clean_text(get_value(item.payload, "location.city"))
            external_id = clean_text(get_value(item.payload, "id", "correlationId")) or str(item.record_number)
            normalized = activity or f"Entra {event_type} for {username or 'unknown identity'}"
            try:
                events.append(CommonEvent(
                    external_event_id=external_id,
                    timestamp=timestamp,
                    original_timestamp=clean_text(timestamp_raw),
                    source_category="identity",
                    source_product="microsoft_entra_id",
                    source_service="identity",
                    source_dataset=self.metadata.connector_id,
                    event_type=event_type,
                    event_action=action,
                    event_outcome=outcome,
                    source_ip=source_ip,
                    username=username,
                    hostname=hostname,
                    raw_message=item.raw_record,
                    normalized_message=normalized,
                    parser_name=self.metadata.connector_id,
                    parser_version=self.metadata.parser_version,
                    parse_status=parse_status,
                    data_quality=findings,
                    attributes={
                        "filename": filename,
                        "app_display_name": app_name,
                        "activity_display_name": activity,
                        "failure_reason": failure_reason,
                        "risk_level": risk,
                        "risk_state": clean_text(get_value(item.payload, "riskState")),
                        "conditional_access_status": conditional_access,
                        "authentication_requirement": clean_text(get_value(item.payload, "authenticationRequirement")),
                        "client_app_used": clean_text(get_value(item.payload, "clientAppUsed")),
                        "is_interactive": get_value(item.payload, "isInteractive"),
                        "country": country,
                        "city": city,
                        "operating_system": clean_text(get_value(item.payload, "deviceDetail.operatingSystem")),
                        "browser": clean_text(get_value(item.payload, "deviceDetail.browser")),
                        "category": clean_text(get_value(item.payload, "category")),
                        "result_reason": clean_text(get_value(item.payload, "resultReason")),
                        "source_format": loaded.format_name,
                    },
                ))
            except ValidationError as error:
                quarantined.append(QuarantinedRecord(
                    record_number=item.record_number, raw_record=item.raw_record,
                    reason_code="common_schema_validation_failed", reason=str(error),
                    parser_name=self.metadata.connector_id, parser_version=self.metadata.parser_version,
                ))
                quality["common_schema_validation_failed"] += 1

        parsed = sum(event.parse_status == ParseStatus.PARSED for event in events)
        partial = sum(event.parse_status == ParseStatus.PARTIAL for event in events)
        non_empty = max(loaded.total_records - loaded.empty_records, 0)
        stats = ParserStatistics(
            connector_id=self.metadata.connector_id,
            parser_name=self.metadata.connector_id,
            parser_version=self.metadata.parser_version,
            total_records=loaded.total_records,
            parsed_records=parsed,
            partial_records=partial,
            quarantined_records=len(quarantined),
            empty_records=loaded.empty_records,
            parse_success_rate=round(len(events) / non_empty, 4) if non_empty else 0.0,
            quality_findings=dict(sorted(quality.items())),
        )
        return ParserResult(
            connector_id=self.metadata.connector_id,
            events=events,
            quarantined_records=quarantined,
            statistics=stats,
            source_metadata={"filename": filename, "source_format": loaded.format_name, "encoding": "utf-8-sig"},
        )
