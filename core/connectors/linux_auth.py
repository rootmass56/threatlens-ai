from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from core.connectors.base import ConnectorMetadata, SecurityLogConnector
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

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

REMOTE_AUTH_PATTERN = re.compile(
    r"(?P<prefix>Failed password for invalid user|Failed password for|"
    r"Accepted (?:password|publickey) for)\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)


class LinuxAuthConnector(SecurityLogConnector):
    """Normalize Linux auth.log/syslog authentication records."""

    metadata = ConnectorMetadata(
        connector_id="linux_auth",
        name="Linux Authentication Log",
        product="linux",
        service="auth",
        category="authentication",
        parser_version="1.0.0",
        supported_extensions=(".log", ".txt"),
        description=(
            "Parses OpenSSH, sudo, PAM and session activity from Linux auth.log-style files."
        ),
    )

    @staticmethod
    def _decode(raw_content: str | bytes) -> str:
        if isinstance(raw_content, bytes):
            return raw_content.decode("utf-8-sig", errors="replace")
        return raw_content.lstrip("\ufeff")

    def validate_source(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
    ) -> SourceValidationResult:
        text = self._decode(raw_content)
        non_empty = [line.strip() for line in text.splitlines() if line.strip()][:30]
        if not non_empty:
            return SourceValidationResult(
                valid=False,
                confidence=0.0,
                connector_id=self.metadata.connector_id,
                reasons=["The source is empty."],
            )
        matched = sum(bool(SYSLOG_PATTERN.match(line.lstrip("\ufeff"))) for line in non_empty)
        auth_markers = sum(
            any(marker in line.lower() for marker in ("sshd", "sudo", "pam_", "authentication"))
            for line in non_empty
        )
        ratio = matched / len(non_empty)
        confidence = min(1.0, ratio * 0.75 + (auth_markers / len(non_empty)) * 0.25)
        reasons = [
            f"{matched}/{len(non_empty)} sampled records match syslog structure.",
            f"{auth_markers}/{len(non_empty)} sampled records contain authentication markers.",
        ]
        if filename and filename.lower().endswith(("auth.log", "secure", ".log", ".txt")):
            confidence = min(1.0, confidence + 0.05)
        return SourceValidationResult(
            valid=ratio >= 0.60 and auth_markers > 0,
            confidence=round(confidence, 3),
            connector_id=self.metadata.connector_id,
            reasons=reasons,
        )

    @staticmethod
    def _parse_timestamp(
        month: str,
        day: str,
        time_value: str,
        *,
        analysis_year: int,
    ) -> tuple[datetime | None, list[DataQualityFinding]]:
        raw_timestamp = f"{month} {day} {time_value}"
        findings = [
            DataQualityFinding(
                code="syslog_year_assumed",
                severity=DataQualitySeverity.INFO,
                field="timestamp",
                raw_value=raw_timestamp,
                message=f"Syslog omitted the year; analysis year {analysis_year} was applied.",
            )
        ]
        try:
            parsed = datetime.strptime(
                f"{analysis_year} {raw_timestamp}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=UTC)
            return parsed, findings
        except ValueError:
            findings.append(
                DataQualityFinding(
                    code="invalid_syslog_timestamp",
                    severity=DataQualitySeverity.ERROR,
                    field="timestamp",
                    raw_value=raw_timestamp,
                    message="The syslog timestamp could not be parsed.",
                )
            )
            return None, findings

    @staticmethod
    def _extract_event(process: str, message: str) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_type": "unknown",
            "event_action": None,
            "event_outcome": None,
            "source_ip": None,
            "source_port": None,
            "username": None,
            "command_line": None,
            "file_path": None,
            "normalized_message": message,
            "attributes": {},
        }

        remote = REMOTE_AUTH_PATTERN.search(message)
        if remote:
            prefix = remote.group("prefix").lower()
            user = remote.group("user")
            ip = remote.group("ip")
            port = int(remote.group("port")) if remote.group("port") else None
            event.update(
                {
                    "source_ip": ip,
                    "source_port": port,
                    "username": user,
                    "event_action": "authentication",
                }
            )
            if prefix.startswith("failed password for invalid user"):
                event.update(
                    {
                        "event_type": "failed_login_invalid_user",
                        "event_outcome": "failure",
                        "normalized_message": f"Failed login for invalid user {user} from {ip}",
                    }
                )
            elif prefix.startswith("failed password for"):
                event.update(
                    {
                        "event_type": "failed_login",
                        "event_outcome": "failure",
                        "normalized_message": f"Failed login for user {user} from {ip}",
                    }
                )
            else:
                event.update(
                    {
                        "event_type": "successful_login",
                        "event_outcome": "success",
                        "normalized_message": f"Successful login for user {user} from {ip}",
                    }
                )
            return event

        if process.lower() == "sudo":
            sudo_match = re.search(
                r"(?P<user>\S+)\s*:\s*.*COMMAND=(?P<command>.+)",
                message,
                re.IGNORECASE,
            )
            if sudo_match:
                command = sudo_match.group("command").strip()
                file_match = re.search(r"(?:cat|less|more|vim|nano)\s+(?P<path>/\S+)", command)
                event.update(
                    {
                        "username": sudo_match.group("user"),
                        "event_type": "sudo_command",
                        "event_action": "privileged_command",
                        "event_outcome": "success",
                        "command_line": command,
                        "file_path": file_match.group("path") if file_match else None,
                        "normalized_message": (
                            f"Sudo command executed by {sudo_match.group('user')}: {command}"
                        ),
                    }
                )
                return event

        pam_failure = re.search(
            r"authentication failure;.*?(?:rhost=(?P<ip>\S*))?.*?(?:user=(?P<user>\S+))?",
            message,
            re.IGNORECASE,
        )
        if pam_failure and "authentication failure" in message.lower():
            ip = pam_failure.groupdict().get("ip") or None
            user = pam_failure.groupdict().get("user") or None
            event.update(
                {
                    "source_ip": ip,
                    "username": user,
                    "event_type": "pam_authentication_failure",
                    "event_action": "authentication",
                    "event_outcome": "failure",
                    "normalized_message": (
                        f"PAM authentication failure for user {user or 'unknown'} "
                        f"from {ip or 'unknown source'}"
                    ),
                }
            )
            return event

        session_match = re.search(
            r"session (?P<state>opened|closed) for user (?P<user>\S+)",
            message,
            re.IGNORECASE,
        )
        if session_match:
            state = session_match.group("state").lower()
            user = session_match.group("user")
            event.update(
                {
                    "username": user,
                    "event_type": f"session_{state}",
                    "event_action": "session",
                    "event_outcome": "success",
                    "normalized_message": f"Session {state} for user {user}",
                }
            )
        return event

    def parse(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> ParserResult:
        options = options or {}
        analysis_year = int(options.get("analysis_year", datetime.now(UTC).year))
        text = self._decode(raw_content)
        events: list[CommonEvent] = []
        quarantined: list[QuarantinedRecord] = []
        quality_counter: Counter[str] = Counter()
        empty_records = 0
        total_records = len(text.splitlines())

        for record_number, source_line in enumerate(text.splitlines(), start=1):
            line = source_line.lstrip("\ufeff").strip()
            if not line:
                empty_records += 1
                continue
            match = SYSLOG_PATTERN.match(line)
            if not match:
                quarantined.append(
                    QuarantinedRecord(
                        record_number=record_number,
                        raw_record=line,
                        reason_code="syslog_structure_mismatch",
                        reason="The record does not match the supported Linux syslog structure.",
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["syslog_structure_mismatch"] += 1
                continue

            extracted = match.groupdict()
            timestamp, findings = self._parse_timestamp(
                extracted["month"],
                extracted["day"],
                extracted["time"],
                analysis_year=analysis_year,
            )
            event_data = self._extract_event(extracted["process"], extracted["message"])
            parse_status = ParseStatus.PARSED
            if event_data["event_type"] == "unknown":
                parse_status = ParseStatus.PARTIAL
                findings.append(
                    DataQualityFinding(
                        code="unsupported_auth_message",
                        severity=DataQualitySeverity.WARNING,
                        field="event_type",
                        raw_value=extracted["message"],
                        message=(
                            "The syslog envelope was parsed, but the authentication message "
                            "did not match a supported event pattern."
                        ),
                    )
                )
            for finding in findings:
                quality_counter[finding.code] += 1

            try:
                events.append(
                    CommonEvent(
                        external_event_id=str(record_number),
                        timestamp=timestamp,
                        original_timestamp=(
                            f"{extracted['month']} {extracted['day']} {extracted['time']}"
                        ),
                        timezone="UTC",
                        source_category=self.metadata.category,
                        source_product=self.metadata.product,
                        source_service=self.metadata.service,
                        source_dataset=self.metadata.connector_id,
                        event_type=event_data["event_type"],
                        event_action=event_data["event_action"],
                        event_outcome=event_data["event_outcome"],
                        source_ip=event_data["source_ip"],
                        source_port=event_data["source_port"],
                        username=event_data["username"],
                        hostname=extracted["hostname"],
                        process_name=extracted["process"],
                        process_id=int(extracted["pid"]) if extracted["pid"] else None,
                        command_line=event_data["command_line"],
                        file_path=event_data["file_path"],
                        raw_message=line,
                        normalized_message=event_data["normalized_message"],
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                        parse_status=parse_status,
                        data_quality=findings,
                        attributes={
                            "filename": filename,
                            "syslog_message": extracted["message"],
                            **event_data["attributes"],
                        },
                    )
                )
            except ValidationError as error:
                quarantined.append(
                    QuarantinedRecord(
                        record_number=record_number,
                        raw_record=line,
                        reason_code="common_schema_validation_failed",
                        reason=str(error),
                        parser_name=self.metadata.connector_id,
                        parser_version=self.metadata.parser_version,
                    )
                )
                quality_counter["common_schema_validation_failed"] += 1

        parsed_records = sum(event.parse_status == ParseStatus.PARSED for event in events)
        partial_records = sum(event.parse_status == ParseStatus.PARTIAL for event in events)
        non_empty = max(total_records - empty_records, 0)
        success_rate = (len(events) / non_empty) if non_empty else 0.0
        statistics = ParserStatistics(
            connector_id=self.metadata.connector_id,
            parser_name=self.metadata.connector_id,
            parser_version=self.metadata.parser_version,
            total_records=total_records,
            parsed_records=parsed_records,
            partial_records=partial_records,
            quarantined_records=len(quarantined),
            empty_records=empty_records,
            parse_success_rate=round(success_rate, 4),
            quality_findings=dict(sorted(quality_counter.items())),
        )
        return ParserResult(
            connector_id=self.metadata.connector_id,
            events=events,
            quarantined_records=quarantined,
            statistics=statistics,
            source_metadata={
                "filename": filename,
                "analysis_year": analysis_year,
                "encoding": "utf-8-sig",
            },
        )
