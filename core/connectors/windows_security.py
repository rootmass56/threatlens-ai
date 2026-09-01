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
    safe_int,
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

WINDOWS_EVENT_MAP: dict[int, tuple[str, str, str, str]] = {
    4624: ("successful_login", "authentication", "success", "authentication"),
    4625: ("failed_login", "authentication", "failure", "authentication"),
    4634: ("logoff", "session", "success", "authentication"),
    4648: ("explicit_credential_logon", "authentication", "success", "authentication"),
    4672: ("special_privileges_assigned", "privilege_assignment", "success", "privilege"),
    4688: ("process_creation", "process_start", "success", "process_creation"),
    4698: ("scheduled_task_created", "persistence", "success", "persistence"),
    4719: ("audit_policy_changed", "policy_change", "success", "defense_evasion"),
    4720: ("user_account_created", "account_create", "success", "account_management"),
    4728: ("group_member_added", "group_membership_change", "success", "account_management"),
    4732: ("group_member_added", "group_membership_change", "success", "account_management"),
    1102: ("audit_log_cleared", "log_clear", "success", "defense_evasion"),
}


class WindowsSecurityConnector(SecurityLogConnector):
    """Normalize Windows Security Event Log JSON/JSONL/CSV exports."""

    metadata = ConnectorMetadata(
        connector_id="windows_security",
        name="Windows Security Events",
        product="windows",
        service="security",
        category="endpoint",
        parser_version="1.0.0",
        supported_extensions=(".json", ".jsonl", ".ndjson", ".csv"),
        description=(
            "Parses Windows Security event exports including authentication, process, "
            "account-management and audit-policy activity."
        ),
    )

    @staticmethod
    def _event_id(record: dict[str, Any]) -> int | None:
        return safe_int(
            get_value(
                record,
                "EventID",
                "EventId",
                "event_id",
                "winlog.event_id",
                "System.EventID",
            )
        )

    def validate_source(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
    ) -> SourceValidationResult:
        loaded = load_structured_records(raw_content, filename=filename)
        sample = loaded.records[:30]
        if not sample:
            return SourceValidationResult(
                valid=False,
                confidence=0.0,
                connector_id=self.metadata.connector_id,
                reasons=["No structured records were available."],
            )
        event_ids = [self._event_id(item.payload) for item in sample]
        id_matches = sum(event_id is not None for event_id in event_ids)
        windows_markers = 0
        sysmon_markers = 0
        for item in sample:
            provider = (
                clean_text(
                    get_value(
                        item.payload,
                        "ProviderName",
                        "Provider.Name",
                        "winlog.provider_name",
                        "source_name",
                    )
                )
                or ""
            )
            channel = (
                clean_text(get_value(item.payload, "Channel", "winlog.channel", "System.Channel"))
                or ""
            )
            marker_text = f"{provider} {channel}".lower()
            windows_markers += int(
                "security" in marker_text or "microsoft-windows-security-auditing" in marker_text
            )
            sysmon_markers += int("sysmon" in marker_text)
        ratio = id_matches / len(sample)
        confidence = ratio * 0.65 + (windows_markers / len(sample)) * 0.35
        if filename and "security" in filename.lower():
            confidence += 0.10
        if sysmon_markers:
            confidence -= min(0.50, sysmon_markers / len(sample))
        confidence = max(0.0, min(1.0, confidence))
        return SourceValidationResult(
            valid=ratio >= 0.60 and sysmon_markers < len(sample) / 2,
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=[
                f"{id_matches}/{len(sample)} sampled records contain an Event ID.",
                f"{windows_markers}/{len(sample)} records contain Windows Security markers.",
                f"{sysmon_markers}/{len(sample)} records contain Sysmon markers.",
            ],
        )

    @staticmethod
    def _username(record: dict[str, Any]) -> str | None:
        domain = clean_text(
            get_value(
                record,
                "TargetDomainName",
                "SubjectDomainName",
                "winlog.event_data.TargetDomainName",
            )
        )
        user = clean_text(
            get_value(
                record,
                "TargetUserName",
                "SubjectUserName",
                "AccountName",
                "User",
                "user.name",
                "winlog.event_data.TargetUserName",
                "winlog.event_data.SubjectUserName",
            )
        )
        if not user or user == "-":
            return None
        return f"{domain}\\{user}" if domain and domain not in {"-", "."} else user

    def parse(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> ParserResult:
        del options
        loaded = load_structured_records(raw_content, filename=filename)
        events: list[CommonEvent] = []
        quarantined = [
            QuarantinedRecord(
                record_number=error.record_number,
                raw_record=error.raw_record,
                reason_code=error.reason_code,
                reason=error.reason,
                parser_name=self.metadata.connector_id,
                parser_version=self.metadata.parser_version,
            )
            for error in loaded.errors
        ]
        quality_counter: Counter[str] = Counter(error.reason_code for error in loaded.errors)

        for item in loaded.records:
            event_id = self._event_id(item.payload)
            if event_id is None:
                quarantined.append(
                    QuarantinedRecord(
                        record_number=item.record_number,
                        raw_record=item.raw_record,
                        reason_code="missing_windows_event_id",
                        reason="The Windows record does not contain a usable Event ID.",
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["missing_windows_event_id"] += 1
                continue

            findings: list[DataQualityFinding] = []
            mapping = WINDOWS_EVENT_MAP.get(event_id)
            if mapping is None:
                event_type, event_action, event_outcome, category = (
                    "windows_security_event",
                    "observe",
                    None,
                    "endpoint",
                )
                findings.append(
                    DataQualityFinding(
                        code="unmapped_windows_event_id",
                        severity=DataQualitySeverity.WARNING,
                        field="event_type",
                        raw_value=str(event_id),
                        message=(
                            "The record was normalized, but this Event ID has no "
                            "specialized mapping."
                        ),
                    )
                )
                quality_counter["unmapped_windows_event_id"] += 1
                parse_status = ParseStatus.PARTIAL
            else:
                event_type, event_action, event_outcome, category = mapping
                parse_status = ParseStatus.PARSED

            timestamp_raw = get_value(
                item.payload,
                "TimeCreated",
                "SystemTime",
                "timestamp",
                "@timestamp",
                "winlog.time_created",
                "System.TimeCreated.SystemTime",
            )
            timestamp = parse_timestamp(timestamp_raw)
            if timestamp is None:
                findings.append(
                    DataQualityFinding(
                        code="missing_or_invalid_timestamp",
                        severity=DataQualitySeverity.WARNING,
                        field="timestamp",
                        raw_value=clean_text(timestamp_raw),
                        message="The Windows event timestamp could not be normalized.",
                    )
                )
                quality_counter["missing_or_invalid_timestamp"] += 1
                parse_status = ParseStatus.PARTIAL

            source_ip = safe_ip(
                get_value(
                    item.payload,
                    "IpAddress",
                    "SourceNetworkAddress",
                    "SourceIp",
                    "source.ip",
                    "winlog.event_data.IpAddress",
                )
            )
            source_port = safe_int(get_value(item.payload, "IpPort", "SourcePort", "source.port"))
            process_name = clean_text(
                get_value(
                    item.payload,
                    "NewProcessName",
                    "ProcessName",
                    "process.executable",
                    "winlog.event_data.NewProcessName",
                )
            )
            parent_process = clean_text(
                get_value(
                    item.payload,
                    "ParentProcessName",
                    "CreatorProcessName",
                    "process.parent.executable",
                    "winlog.event_data.ParentProcessName",
                )
            )
            command_line = clean_text(
                get_value(
                    item.payload,
                    "CommandLine",
                    "ProcessCommandLine",
                    "process.command_line",
                    "winlog.event_data.CommandLine",
                )
            )
            username = self._username(item.payload)
            hostname = clean_text(
                get_value(
                    item.payload,
                    "Computer",
                    "ComputerName",
                    "Hostname",
                    "host.name",
                    "winlog.computer_name",
                    "System.Computer",
                )
            )
            record_id = clean_text(
                get_value(
                    item.payload,
                    "EventRecordID",
                    "RecordId",
                    "winlog.record_id",
                    "System.EventRecordID",
                )
            ) or str(item.record_number)
            logon_type = clean_text(
                get_value(item.payload, "LogonType", "winlog.event_data.LogonType")
            )
            message = clean_text(get_value(item.payload, "Message", "message"))
            normalized = message or f"Windows Security Event {event_id}: {event_type}"

            try:
                events.append(
                    CommonEvent(
                        external_event_id=record_id,
                        timestamp=timestamp,
                        original_timestamp=clean_text(timestamp_raw),
                        source_category=category,
                        source_product="windows",
                        source_service="security",
                        source_dataset=self.metadata.connector_id,
                        event_type=event_type,
                        event_action=event_action,
                        event_outcome=event_outcome,
                        source_ip=source_ip,
                        source_port=source_port,
                        username=username,
                        hostname=hostname,
                        process_name=process_name,
                        process_id=safe_int(
                            get_value(
                                item.payload,
                                "NewProcessId",
                                "ProcessId",
                                "process.pid",
                                "winlog.event_data.NewProcessId",
                            )
                        ),
                        parent_process_name=parent_process,
                        command_line=command_line,
                        raw_message=item.raw_record,
                        normalized_message=normalized,
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                        parse_status=parse_status,
                        data_quality=findings,
                        attributes={
                            "filename": filename,
                            "event_code": event_id,
                            "provider": clean_text(
                                get_value(
                                    item.payload,
                                    "ProviderName",
                                    "Provider.Name",
                                    "winlog.provider_name",
                                )
                            ),
                            "channel": clean_text(
                                get_value(item.payload, "Channel", "winlog.channel")
                            ),
                            "logon_type": logon_type,
                            "target_user": username,
                            "subject_user": clean_text(
                                get_value(
                                    item.payload,
                                    "SubjectUserName",
                                    "winlog.event_data.SubjectUserName",
                                )
                            ),
                            "status": clean_text(
                                get_value(item.payload, "Status", "winlog.event_data.Status")
                            ),
                            "sub_status": clean_text(
                                get_value(item.payload, "SubStatus", "winlog.event_data.SubStatus")
                            ),
                            "source_format": loaded.format_name,
                        },
                    )
                )
            except ValidationError as error:
                quarantined.append(
                    QuarantinedRecord(
                        record_number=item.record_number,
                        raw_record=item.raw_record,
                        reason_code="common_schema_validation_failed",
                        reason=str(error),
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["common_schema_validation_failed"] += 1

        parsed_records = sum(event.parse_status == ParseStatus.PARSED for event in events)
        partial_records = sum(event.parse_status == ParseStatus.PARTIAL for event in events)
        non_empty = max(loaded.total_records - loaded.empty_records, 0)
        statistics = ParserStatistics(
            connector_id=self.metadata.connector_id,
            parser_name=self.metadata.connector_id,
            parser_version=self.metadata.parser_version,
            total_records=loaded.total_records,
            parsed_records=parsed_records,
            partial_records=partial_records,
            quarantined_records=len(quarantined),
            empty_records=loaded.empty_records,
            parse_success_rate=round(len(events) / non_empty, 4) if non_empty else 0.0,
            quality_findings=dict(sorted(quality_counter.items())),
        )
        return ParserResult(
            connector_id=self.metadata.connector_id,
            events=events,
            quarantined_records=quarantined,
            statistics=statistics,
            source_metadata={
                "filename": filename,
                "source_format": loaded.format_name,
                "encoding": "utf-8-sig",
            },
        )
