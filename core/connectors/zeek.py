from __future__ import annotations

import json
from collections import Counter
from typing import Any

from pydantic import ValidationError

from core.connectors.base import ConnectorMetadata, SecurityLogConnector
from core.connectors.structured import (
    StructuredLoadResult,
    StructuredRecord,
    StructuredRecordError,
    clean_text,
    decode_text,
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


class ZeekConnector(SecurityLogConnector):
    """Normalize Zeek TSV or JSON logs."""

    metadata = ConnectorMetadata(
        connector_id="zeek",
        name="Zeek Network Logs",
        product="zeek",
        service="network_monitor",
        category="network",
        parser_version="1.0.0",
        supported_extensions=(".log", ".json", ".jsonl", ".ndjson"),
        description=("Parses Zeek conn, dns, http and ssl/tls logs in native TSV or JSON format."),
    )

    @staticmethod
    def _decode_separator(raw_value: str) -> str:
        value = raw_value.strip()
        if value.startswith("\\x") and len(value) == 4:
            try:
                return bytes.fromhex(value[2:]).decode("latin-1")
            except ValueError:
                return "\t"
        return value or "\t"

    @classmethod
    def _load_zeek_records(
        cls,
        raw_content: str | bytes,
        *,
        filename: str | None,
    ) -> StructuredLoadResult:
        text = decode_text(raw_content)
        if text.lstrip().startswith(("{", "[")):
            return load_structured_records(text, filename=filename)

        lines = text.splitlines()
        separator = "\t"
        fields: list[str] | None = None
        records: list[StructuredRecord] = []
        errors: list[StructuredRecordError] = []
        empty_records = 0
        data_records = 0

        for record_number, source_line in enumerate(lines, start=1):
            line = source_line.rstrip("\r\n")
            if not line.strip():
                empty_records += 1
                continue
            if line.startswith("#separator"):
                _, _, value = line.partition(" ")
                separator = cls._decode_separator(value)
                continue
            if line.startswith("#fields"):
                body = line[len("#fields") :].lstrip(separator + " ")
                fields = body.split(separator)
                continue
            if line.startswith("#"):
                continue

            data_records += 1
            if not fields:
                errors.append(
                    StructuredRecordError(
                        record_number=record_number,
                        raw_record=line,
                        reason_code="missing_zeek_fields_header",
                        reason="Zeek TSV input must declare a #fields header before data records.",
                    )
                )
                continue
            values = line.split(separator)
            if len(values) != len(fields):
                errors.append(
                    StructuredRecordError(
                        record_number=record_number,
                        raw_record=line,
                        reason_code="zeek_field_count_mismatch",
                        reason=(
                            f"Expected {len(fields)} fields from the Zeek header but received "
                            f"{len(values)}."
                        ),
                    )
                )
                continue
            payload = dict(zip(fields, values, strict=True))
            records.append(StructuredRecord(record_number, payload, line))

        return StructuredLoadResult(
            records=records,
            errors=errors,
            total_records=data_records + empty_records,
            empty_records=empty_records,
            format_name="zeek_tsv",
        )

    @staticmethod
    def _log_type(record: dict[str, Any], filename: str | None) -> str:
        lower_name = (filename or "").lower()
        for log_type in ("conn", "dns", "http", "ssl", "tls"):
            if f"{log_type}.log" in lower_name or f"_{log_type}." in lower_name:
                return "ssl" if log_type == "tls" else log_type
        if get_value(record, "query", "qtype_name") is not None:
            return "dns"
        if get_value(record, "uri", "method", "status_code") is not None:
            return "http"
        if get_value(record, "server_name", "cipher", "curve") is not None:
            return "ssl"
        if get_value(record, "id.orig_h", "id.resp_h", "conn_state") is not None:
            return "conn"
        return "unknown"

    def validate_source(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
    ) -> SourceValidationResult:
        text = decode_text(raw_content)
        header_marker = "#fields" in text[:5000]
        loaded = self._load_zeek_records(text, filename=filename)
        sample = loaded.records[:30]
        if not sample:
            return SourceValidationResult(
                valid=False,
                confidence=0.0,
                connector_id=self.metadata.connector_id,
                reasons=["No Zeek records were available."],
            )
        zeek_markers = sum(
            get_value(item.payload, "uid") is not None
            or get_value(item.payload, "id.orig_h") is not None
            for item in sample
        )
        recognized = sum(self._log_type(item.payload, filename) != "unknown" for item in sample)
        suricata_markers = sum(
            get_value(item.payload, "event_type") is not None
            and get_value(item.payload, "flow_id") is not None
            for item in sample
        )
        confidence = (
            (zeek_markers / len(sample)) * 0.45
            + (recognized / len(sample)) * 0.35
            + (0.20 if header_marker else 0.0)
        )
        if filename and "zeek" in filename.lower():
            confidence += 0.10
        if suricata_markers:
            confidence -= 0.40
        confidence = max(0.0, min(1.0, confidence))
        return SourceValidationResult(
            valid=recognized / len(sample) >= 0.60 and suricata_markers == 0,
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=[
                f"{zeek_markers}/{len(sample)} records contain Zeek entity fields.",
                f"{recognized}/{len(sample)} records match conn/dns/http/ssl schemas.",
                f"Native #fields header detected: {header_marker}.",
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
        loaded = self._load_zeek_records(raw_content, filename=filename)
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
            log_type = self._log_type(item.payload, filename)
            findings: list[DataQualityFinding] = []
            if log_type == "conn":
                event_type, event_action = "network_connection", "network_connect"
            elif log_type == "dns":
                event_type, event_action = "dns_query", "dns_query"
            elif log_type == "http":
                event_type, event_action = "http_request", "http_request"
            elif log_type == "ssl":
                event_type, event_action = "tls_handshake", "tls_handshake"
            else:
                event_type, event_action = "zeek_event", "observe"
                findings.append(
                    DataQualityFinding(
                        code="unsupported_zeek_log_type",
                        severity=DataQualitySeverity.WARNING,
                        field="event_type",
                        raw_value=filename,
                        message="The Zeek record could not be assigned to conn, dns, http or ssl.",
                    )
                )
                quality_counter["unsupported_zeek_log_type"] += 1

            timestamp_raw = get_value(item.payload, "ts", "timestamp", "@timestamp")
            timestamp = parse_timestamp(timestamp_raw)
            parse_status = ParseStatus.PARSED if log_type != "unknown" else ParseStatus.PARTIAL
            if timestamp is None:
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="missing_or_invalid_timestamp",
                        severity=DataQualitySeverity.WARNING,
                        field="timestamp",
                        raw_value=clean_text(timestamp_raw),
                        message="The Zeek timestamp could not be normalized.",
                    )
                )
                quality_counter["missing_or_invalid_timestamp"] += 1

            domain = clean_text(get_value(item.payload, "query", "server_name", "host"))
            uri = clean_text(get_value(item.payload, "uri"))
            url = None
            if uri:
                if uri.startswith(("http://", "https://")):
                    url = uri
                elif domain:
                    url = f"http://{domain}{uri}"
                else:
                    url = uri
            normalized = {
                "conn": "Zeek network connection",
                "dns": f"Zeek DNS query for {domain or 'unknown domain'}",
                "http": f"Zeek HTTP request to {url or domain or 'unknown destination'}",
                "ssl": f"Zeek TLS handshake with {domain or 'unknown server'}",
            }.get(log_type, "Zeek event")

            try:
                events.append(
                    CommonEvent(
                        external_event_id=clean_text(get_value(item.payload, "uid"))
                        or str(item.record_number),
                        timestamp=timestamp,
                        original_timestamp=clean_text(timestamp_raw),
                        source_category="network",
                        source_product="zeek",
                        source_service="network_monitor",
                        source_dataset=self.metadata.connector_id,
                        event_type=event_type,
                        event_action=event_action,
                        event_outcome=None,
                        source_ip=safe_ip(get_value(item.payload, "id.orig_h", "source.ip")),
                        source_port=safe_int(get_value(item.payload, "id.orig_p", "source.port")),
                        destination_ip=safe_ip(
                            get_value(item.payload, "id.resp_h", "destination.ip")
                        ),
                        destination_port=safe_int(
                            get_value(item.payload, "id.resp_p", "destination.port")
                        ),
                        hostname=clean_text(
                            get_value(item.payload, "host_name", "hostname", "observer.hostname")
                        ),
                        domain=domain,
                        url=url,
                        raw_message=(
                            item.raw_record
                            if loaded.format_name == "zeek_tsv"
                            else json.dumps(item.payload, ensure_ascii=False, default=str)
                        ),
                        normalized_message=normalized,
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                        parse_status=parse_status,
                        data_quality=findings,
                        attributes={
                            "filename": filename,
                            "zeek_log_type": log_type,
                            "uid": clean_text(get_value(item.payload, "uid")),
                            "protocol": clean_text(get_value(item.payload, "proto")),
                            "service": clean_text(get_value(item.payload, "service")),
                            "duration": clean_text(get_value(item.payload, "duration")),
                            "conn_state": clean_text(get_value(item.payload, "conn_state")),
                            "history": clean_text(get_value(item.payload, "history")),
                            "orig_bytes": safe_int(get_value(item.payload, "orig_bytes")),
                            "resp_bytes": safe_int(get_value(item.payload, "resp_bytes")),
                            "qtype_name": clean_text(get_value(item.payload, "qtype_name")),
                            "rcode_name": clean_text(get_value(item.payload, "rcode_name")),
                            "http_method": clean_text(get_value(item.payload, "method")),
                            "http_status": safe_int(get_value(item.payload, "status_code")),
                            "tls_version": clean_text(get_value(item.payload, "version")),
                            "tls_cipher": clean_text(get_value(item.payload, "cipher")),
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
