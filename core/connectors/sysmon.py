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

SYSMON_EVENT_MAP: dict[int, tuple[str, str, str]] = {
    1: ("process_creation", "process_start", "process_creation"),
    3: ("network_connection", "network_connect", "network"),
    5: ("process_terminated", "process_stop", "process_creation"),
    6: ("driver_loaded", "driver_load", "driver"),
    7: ("image_loaded", "image_load", "module_load"),
    8: ("create_remote_thread", "remote_thread", "process_injection"),
    10: ("process_access", "process_access", "credential_access"),
    11: ("file_created", "file_create", "file"),
    12: ("registry_object_created_deleted", "registry_change", "registry"),
    13: ("registry_value_set", "registry_change", "registry"),
    22: ("dns_query", "dns_query", "network"),
    23: ("file_deleted", "file_delete", "file"),
}


class SysmonConnector(SecurityLogConnector):
    """Normalize Microsoft Sysmon JSON/JSONL/CSV exports."""

    metadata = ConnectorMetadata(
        connector_id="windows_sysmon",
        name="Microsoft Sysmon Events",
        product="windows",
        service="sysmon",
        category="endpoint",
        parser_version="1.0.0",
        supported_extensions=(".json", ".jsonl", ".ndjson", ".csv"),
        description=(
            "Parses Sysmon process, network, DNS, registry, file and process-access telemetry."
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
        id_matches = 0
        sysmon_markers = 0
        sysmon_fields = 0
        for item in sample:
            event_id = self._event_id(item.payload)
            id_matches += int(event_id in SYSMON_EVENT_MAP)
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
            sysmon_markers += int("sysmon" in provider.lower())
            sysmon_fields += int(
                any(
                    get_value(item.payload, field) is not None
                    for field in ("Image", "ProcessGuid", "UtcTime", "TargetImage", "QueryName")
                )
            )
        confidence = (
            (id_matches / len(sample)) * 0.45
            + (sysmon_markers / len(sample)) * 0.35
            + (sysmon_fields / len(sample)) * 0.20
        )
        if filename and "sysmon" in filename.lower():
            confidence += 0.10
        confidence = min(1.0, confidence)
        return SourceValidationResult(
            valid=id_matches / len(sample) >= 0.60
            and (sysmon_markers > 0 or sysmon_fields / len(sample) >= 0.60),
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=[
                f"{id_matches}/{len(sample)} records use supported Sysmon Event IDs.",
                f"{sysmon_markers}/{len(sample)} records contain a Sysmon provider marker.",
                f"{sysmon_fields}/{len(sample)} records contain Sysmon-specific fields.",
            ],
        )

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
                        reason_code="missing_sysmon_event_id",
                        reason="The Sysmon record does not contain a usable Event ID.",
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["missing_sysmon_event_id"] += 1
                continue

            findings: list[DataQualityFinding] = []
            mapping = SYSMON_EVENT_MAP.get(event_id)
            if mapping is None:
                event_type, event_action, category = (
                    "sysmon_event",
                    "observe",
                    "endpoint",
                )
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="unmapped_sysmon_event_id",
                        severity=DataQualitySeverity.WARNING,
                        field="event_type",
                        raw_value=str(event_id),
                        message="The Sysmon Event ID has no specialized ThreatLens mapping.",
                    )
                )
                quality_counter["unmapped_sysmon_event_id"] += 1
            else:
                event_type, event_action, category = mapping
                parse_status = ParseStatus.PARSED

            timestamp_raw = get_value(
                item.payload,
                "UtcTime",
                "TimeCreated",
                "SystemTime",
                "@timestamp",
                "timestamp",
                "winlog.time_created",
            )
            timestamp = parse_timestamp(timestamp_raw)
            if timestamp is None:
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="missing_or_invalid_timestamp",
                        severity=DataQualitySeverity.WARNING,
                        field="timestamp",
                        raw_value=clean_text(timestamp_raw),
                        message="The Sysmon event timestamp could not be normalized.",
                    )
                )
                quality_counter["missing_or_invalid_timestamp"] += 1

            process_name = clean_text(
                get_value(item.payload, "Image", "ProcessName", "process.executable")
            )
            parent_process = clean_text(
                get_value(
                    item.payload,
                    "ParentImage",
                    "ParentProcessName",
                    "process.parent.executable",
                )
            )
            command_line = clean_text(
                get_value(item.payload, "CommandLine", "process.command_line")
            )
            target_image = clean_text(
                get_value(item.payload, "TargetImage", "winlog.event_data.TargetImage")
            )
            file_path = clean_text(
                get_value(item.payload, "TargetFilename", "FileName", "file.path")
            )
            domain = clean_text(get_value(item.payload, "QueryName", "dns.question.name"))
            hostname = clean_text(
                get_value(
                    item.payload,
                    "Computer",
                    "ComputerName",
                    "Hostname",
                    "host.name",
                    "winlog.computer_name",
                )
            )
            username = clean_text(
                get_value(item.payload, "User", "user.name", "winlog.event_data.User")
            )
            source_ip = safe_ip(get_value(item.payload, "SourceIp", "source.ip"))
            destination_ip = safe_ip(
                get_value(item.payload, "DestinationIp", "DestinationIpV6", "destination.ip")
            )
            source_port = safe_int(get_value(item.payload, "SourcePort", "source.port"))
            destination_port = safe_int(
                get_value(item.payload, "DestinationPort", "destination.port")
            )
            message = clean_text(get_value(item.payload, "Message", "message"))
            normalized = message or f"Sysmon Event {event_id}: {event_type}"

            try:
                events.append(
                    CommonEvent(
                        external_event_id=clean_text(
                            get_value(item.payload, "EventRecordID", "RecordId", "winlog.record_id")
                        )
                        or str(item.record_number),
                        timestamp=timestamp,
                        original_timestamp=clean_text(timestamp_raw),
                        source_category=category,
                        source_product="windows",
                        source_service="sysmon",
                        source_dataset=self.metadata.connector_id,
                        event_type=event_type,
                        event_action=event_action,
                        event_outcome="success",
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        username=username,
                        hostname=hostname,
                        process_name=process_name,
                        process_id=safe_int(get_value(item.payload, "ProcessId", "process.pid")),
                        parent_process_name=parent_process,
                        command_line=command_line,
                        file_path=file_path,
                        domain=domain,
                        raw_message=item.raw_record,
                        normalized_message=normalized,
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                        parse_status=parse_status,
                        data_quality=findings,
                        attributes={
                            "filename": filename,
                            "event_code": event_id,
                            "process_guid": clean_text(
                                get_value(
                                    item.payload,
                                    "ProcessGuid",
                                    "winlog.event_data.ProcessGuid",
                                )
                            ),
                            "parent_process_guid": clean_text(
                                get_value(item.payload, "ParentProcessGuid")
                            ),
                            "target_image": target_image,
                            "target_object": clean_text(
                                get_value(item.payload, "TargetObject", "registry.path")
                            ),
                            "details": clean_text(get_value(item.payload, "Details")),
                            "granted_access": clean_text(get_value(item.payload, "GrantedAccess")),
                            "protocol": clean_text(
                                get_value(item.payload, "Protocol", "network.transport")
                            ),
                            "query_status": clean_text(get_value(item.payload, "QueryStatus")),
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
