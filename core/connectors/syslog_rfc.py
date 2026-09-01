from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime

from core.connectors.base import ConnectorMetadata, SecurityLogConnector
from core.connectors.structured import clean_text, get_value, load_structured_records, parse_timestamp, safe_ip
from core.schema import CommonEvent, ParserResult, ParserStatistics, ParseStatus, SourceValidationResult

RFC3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<msg>.*)$")


class SyslogRfcConnector(SecurityLogConnector):
    """Normalize durable syslog collector envelopes into common events."""
    metadata = ConnectorMetadata(
        connector_id="syslog_rfc",
        name="RFC Syslog Stream",
        product="syslog",
        service="syslog",
        category="network",
        parser_version="1.0.0",
        supported_extensions=(".json", ".jsonl", ".ndjson"),
        description="Parses RFC3164/RFC5424-like syslog envelopes received through the Batch 6 UDP collector.",
    )

    def validate_source(self, raw_content: str | bytes, *, filename: str | None = None) -> SourceValidationResult:
        loaded = load_structured_records(raw_content, filename=filename)
        sample = loaded.records[:30]
        matches = sum(1 for item in sample if get_value(item.payload, "message", "raw_message") is not None)
        return SourceValidationResult(valid=bool(sample) and matches >= max(1, len(sample)//2), confidence=round(matches/max(len(sample),1),3), connector_id=self.metadata.connector_id, reasons=[f"{matches}/{len(sample)} records contain syslog message content."])

    def parse(self, raw_content: str | bytes, *, filename: str | None = None, options: dict | None = None) -> ParserResult:
        del options
        loaded = load_structured_records(raw_content, filename=filename)
        events=[]; quality=Counter()
        for item in loaded.records:
            message=clean_text(get_value(item.payload,"message","raw_message")) or item.raw_record
            received=parse_timestamp(get_value(item.payload,"received_at","timestamp")) or datetime.now(UTC)
            source_ip=safe_ip(get_value(item.payload,"source_ip"))
            hostname=clean_text(get_value(item.payload,"hostname"))
            facility=None; severity=None
            m=RFC3164.match(message)
            normalized=message
            if m:
                hostname=hostname or m.group("host")
                normalized=m.group("msg")
                if m.group("pri"):
                    pri=int(m.group("pri")); facility=pri//8; severity=pri%8
            events.append(CommonEvent(
                external_event_id=clean_text(get_value(item.payload,"client_event_id")) or str(item.record_number),
                timestamp=received,
                original_timestamp=clean_text(get_value(item.payload,"received_at","timestamp")),
                source_category="network", source_product="syslog", source_service="syslog", source_dataset="syslog_rfc",
                event_type="syslog_message", event_action="observe", event_outcome=None,
                source_ip=source_ip, hostname=hostname, raw_message=message, normalized_message=normalized,
                parser_name=self.metadata.connector_id, parser_version=self.metadata.parser_version,
                parse_status=ParseStatus.PARSED, data_quality=[],
                attributes={"facility":facility,"severity_code":severity,"transport":get_value(item.payload,"transport",default="udp"),"source_format":loaded.format_name},
            ))
        non_empty=max(loaded.total_records-loaded.empty_records,0)
        stats=ParserStatistics(connector_id=self.metadata.connector_id,parser_name=self.metadata.connector_id,parser_version=self.metadata.parser_version,total_records=loaded.total_records,parsed_records=len(events),partial_records=0,quarantined_records=len(loaded.errors),empty_records=loaded.empty_records,parse_success_rate=round(len(events)/non_empty,4) if non_empty else 0.0,quality_findings=dict(quality))
        return ParserResult(connector_id=self.metadata.connector_id,events=events,quarantined_records=[],statistics=stats,source_metadata={"filename":filename,"source_format":loaded.format_name})
