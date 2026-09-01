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

SURICATA_EVENT_MAP: dict[str, tuple[str, str, str]] = {
    "alert": ("ids_alert", "alert", "network"),
    "dns": ("dns_query", "dns_query", "network"),
    "http": ("http_request", "http_request", "network"),
    "tls": ("tls_handshake", "tls_handshake", "network"),
    "flow": ("network_flow", "network_flow", "network"),
    "ssh": ("ssh_session", "ssh_session", "network"),
    "fileinfo": ("network_file", "file_transfer", "network"),
}


class SuricataEveConnector(SecurityLogConnector):
    """Normalize Suricata EVE JSON telemetry."""

    metadata = ConnectorMetadata(
        connector_id="suricata_eve",
        name="Suricata EVE JSON",
        product="suricata",
        service="eve",
        category="network",
        parser_version="1.0.0",
        supported_extensions=(".json", ".jsonl", ".ndjson", ".log"),
        description=("Parses Suricata alert, DNS, HTTP, TLS, flow, SSH and fileinfo EVE records."),
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
        event_type_matches = sum(
            clean_text(get_value(item.payload, "event_type")) in SURICATA_EVENT_MAP
            for item in sample
        )
        network_fields = sum(
            get_value(item.payload, "src_ip") is not None
            and get_value(item.payload, "dest_ip") is not None
            for item in sample
        )
        eve_markers = sum(
            any(key in item.payload for key in ("flow_id", "community_id", "app_proto"))
            for item in sample
        )
        confidence = (
            (event_type_matches / len(sample)) * 0.55
            + (network_fields / len(sample)) * 0.25
            + (eve_markers / len(sample)) * 0.20
        )
        if filename and any(marker in filename.lower() for marker in ("eve", "suricata")):
            confidence += 0.10
        confidence = min(1.0, confidence)
        return SourceValidationResult(
            valid=event_type_matches / len(sample) >= 0.60,
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=[
                f"{event_type_matches}/{len(sample)} records contain supported EVE event types.",
                f"{network_fields}/{len(sample)} records contain source and destination IPs.",
                f"{eve_markers}/{len(sample)} records contain EVE-specific metadata.",
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
            source_event_type = clean_text(get_value(item.payload, "event_type"))
            if source_event_type is None:
                quarantined.append(
                    QuarantinedRecord(
                        record_number=item.record_number,
                        raw_record=item.raw_record,
                        reason_code="missing_suricata_event_type",
                        reason="The EVE record does not contain event_type.",
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["missing_suricata_event_type"] += 1
                continue

            mapping = SURICATA_EVENT_MAP.get(source_event_type)
            findings: list[DataQualityFinding] = []
            if mapping is None:
                event_type, event_action, category = (
                    "suricata_event",
                    "observe",
                    "network",
                )
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="unsupported_suricata_event_type",
                        severity=DataQualitySeverity.WARNING,
                        field="event_type",
                        raw_value=source_event_type,
                        message=(
                            "The EVE envelope was parsed, but this event type is not specialized."
                        ),
                    )
                )
                quality_counter["unsupported_suricata_event_type"] += 1
            else:
                event_type, event_action, category = mapping
                parse_status = ParseStatus.PARSED

            timestamp_raw = get_value(item.payload, "timestamp", "@timestamp")
            timestamp = parse_timestamp(timestamp_raw)
            if timestamp is None:
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="missing_or_invalid_timestamp",
                        severity=DataQualitySeverity.WARNING,
                        field="timestamp",
                        raw_value=clean_text(timestamp_raw),
                        message="The EVE timestamp could not be normalized.",
                    )
                )
                quality_counter["missing_or_invalid_timestamp"] += 1

            alert_signature = clean_text(get_value(item.payload, "alert.signature"))
            alert_category = clean_text(get_value(item.payload, "alert.category"))
            dns_name = clean_text(
                get_value(
                    item.payload,
                    "dns.rrname",
                    "dns.query.rrname",
                    "dns.query",
                )
            )
            http_host = clean_text(get_value(item.payload, "http.hostname", "http.host"))
            http_url = clean_text(get_value(item.payload, "http.url"))
            tls_sni = clean_text(get_value(item.payload, "tls.sni", "tls.subject"))
            domain = dns_name or tls_sni or http_host
            url = None
            if http_url:
                if http_url.startswith(("http://", "https://")):
                    url = http_url
                elif http_host:
                    url = f"http://{http_host}{http_url}"
                else:
                    url = http_url
            normalized = (
                alert_signature
                or dns_name
                or url
                or tls_sni
                or f"Suricata {source_event_type} event"
            )

            try:
                events.append(
                    CommonEvent(
                        external_event_id=clean_text(
                            get_value(item.payload, "event_id", "flow_id", "community_id")
                        )
                        or str(item.record_number),
                        timestamp=timestamp,
                        original_timestamp=clean_text(timestamp_raw),
                        source_category=category,
                        source_product="suricata",
                        source_service="eve",
                        source_dataset=self.metadata.connector_id,
                        event_type=event_type,
                        event_action=event_action,
                        event_outcome=(
                            "failure"
                            if clean_text(get_value(item.payload, "alert.action")) == "blocked"
                            else None
                        ),
                        source_ip=safe_ip(get_value(item.payload, "src_ip", "source.ip")),
                        source_port=safe_int(get_value(item.payload, "src_port", "source.port")),
                        destination_ip=safe_ip(
                            get_value(item.payload, "dest_ip", "destination.ip")
                        ),
                        destination_port=safe_int(
                            get_value(item.payload, "dest_port", "destination.port")
                        ),
                        hostname=clean_text(
                            get_value(item.payload, "host", "hostname", "observer.hostname")
                        ),
                        file_path=clean_text(
                            get_value(item.payload, "fileinfo.filename", "fileinfo.stored")
                        ),
                        domain=domain,
                        url=url,
                        raw_message=item.raw_record,
                        normalized_message=normalized,
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                        parse_status=parse_status,
                        data_quality=findings,
                        attributes={
                            "filename": filename,
                            "eve_event_type": source_event_type,
                            "flow_id": clean_text(get_value(item.payload, "flow_id")),
                            "community_id": clean_text(get_value(item.payload, "community_id")),
                            "protocol": clean_text(get_value(item.payload, "proto")),
                            "app_proto": clean_text(get_value(item.payload, "app_proto")),
                            "signature": alert_signature,
                            "signature_id": safe_int(get_value(item.payload, "alert.signature_id")),
                            "signature_severity": safe_int(
                                get_value(item.payload, "alert.severity")
                            ),
                            "alert_category": alert_category,
                            "alert_action": clean_text(get_value(item.payload, "alert.action")),
                            "dns_type": clean_text(get_value(item.payload, "dns.type")),
                            "dns_rrtype": clean_text(
                                get_value(item.payload, "dns.rrtype", "dns.query.rrtype")
                            ),
                            "http_method": clean_text(get_value(item.payload, "http.http_method")),
                            "http_status": safe_int(get_value(item.payload, "http.status")),
                            "tls_version": clean_text(get_value(item.payload, "tls.version")),
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
