from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pandas as pd


@dataclass(frozen=True)
class StructuredRecord:
    record_number: int
    payload: dict[str, Any]
    raw_record: str


@dataclass(frozen=True)
class StructuredRecordError:
    record_number: int
    raw_record: str
    reason_code: str
    reason: str


@dataclass(frozen=True)
class StructuredLoadResult:
    records: list[StructuredRecord]
    errors: list[StructuredRecordError]
    total_records: int
    empty_records: int
    format_name: str


def decode_text(raw_content: str | bytes) -> str:
    if isinstance(raw_content, bytes):
        return raw_content.decode("utf-8-sig", errors="replace")
    return raw_content.lstrip("\ufeff")


def _normalize_key(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def flatten_record(record: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in record.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        flattened[path] = value
        if isinstance(value, dict):
            flattened.update(flatten_record(value, path))
    return flattened


def get_value(record: dict[str, Any], *candidates: str, default: Any = None) -> Any:
    flattened = flatten_record(record)
    normalized = {_normalize_key(key): value for key, value in flattened.items()}
    for candidate in candidates:
        if candidate in flattened:
            value = flattened[candidate]
            if value not in (None, "", "-", "(empty)"):
                return value
        value = normalized.get(_normalize_key(candidate))
        if value not in (None, "", "-", "(empty)"):
            return value
    return default


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        missing = False
    if isinstance(missing, bool) and missing:
        return None
    text = str(value).strip()
    if text.lower() in {"", "-", "none", "null", "nan", "nat", "<na>"}:
        return None
    return text


def safe_ip(value: Any) -> str | None:
    text = clean_text(value)
    if text is None or text in {"0.0.0.0", "::"}:
        return None
    candidate = text.strip("[]")
    if candidate.lower().startswith("::ffff:"):
        candidate = candidate[7:]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def safe_int(value: Any) -> int | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = clean_text(value)
    if text is None:
        return None
    try:
        number = float(text)
    except ValueError:
        number = None
    if number is not None:
        unit = "ms" if abs(number) >= 10_000_000_000 else "s"
        parsed = pd.to_datetime(number, unit=unit, errors="coerce", utc=True)
    else:
        parsed = pd.to_datetime(text, errors="coerce", utc=True)
    if pd.isna(parsed):
        return None
    return parsed.to_pydatetime()


def _json_records(text: str) -> StructuredLoadResult:
    stripped = text.strip()
    if not stripped:
        return StructuredLoadResult([], [], 0, 0, "json")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[StructuredRecord] = []
        errors: list[StructuredRecordError] = []
        empty_records = 0
        lines = text.splitlines()
        for record_number, line in enumerate(lines, start=1):
            source = line.strip()
            if not source:
                empty_records += 1
                continue
            try:
                item = json.loads(source)
            except json.JSONDecodeError as error:
                errors.append(
                    StructuredRecordError(
                        record_number=record_number,
                        raw_record=source,
                        reason_code="invalid_json_record",
                        reason=f"JSON decoding failed: {error.msg}.",
                    )
                )
                continue
            if not isinstance(item, dict):
                errors.append(
                    StructuredRecordError(
                        record_number=record_number,
                        raw_record=source,
                        reason_code="json_record_not_object",
                        reason="Each JSON line must contain one object.",
                    )
                )
                continue
            records.append(StructuredRecord(record_number, item, source))
        return StructuredLoadResult(
            records=records,
            errors=errors,
            total_records=len(lines),
            empty_records=empty_records,
            format_name="jsonl",
        )

    if isinstance(payload, dict):
        container = next(
            (
                payload[key]
                for key in ("events", "Events", "records", "Records", "items", "Items")
                if isinstance(payload.get(key), list)
            ),
            None,
        )
        items = container if container is not None else [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        items = []

    records = []
    errors = []
    for record_number, item in enumerate(items, start=1):
        raw_record = json.dumps(item, ensure_ascii=False, default=str)
        if not isinstance(item, dict):
            errors.append(
                StructuredRecordError(
                    record_number=record_number,
                    raw_record=raw_record,
                    reason_code="json_record_not_object",
                    reason="Each JSON record must contain one object.",
                )
            )
            continue
        records.append(StructuredRecord(record_number, item, raw_record))
    return StructuredLoadResult(
        records=records,
        errors=errors,
        total_records=len(items),
        empty_records=0,
        format_name="json",
    )


def _csv_records(text: str) -> StructuredLoadResult:
    stream = io.StringIO(text)
    reader = csv.DictReader(stream)
    records: list[StructuredRecord] = []
    errors: list[StructuredRecordError] = []
    empty_records = 0
    total_records = 0
    for row_number, row in enumerate(reader, start=2):
        total_records += 1
        if not any(clean_text(value) for value in row.values()):
            empty_records += 1
            continue
        payload = {str(key): value for key, value in row.items() if key is not None}
        raw_record = json.dumps(payload, ensure_ascii=False, default=str)
        records.append(StructuredRecord(row_number, payload, raw_record))
    return StructuredLoadResult(
        records=records,
        errors=errors,
        total_records=total_records,
        empty_records=empty_records,
        format_name="csv",
    )


def load_structured_records(
    raw_content: str | bytes,
    *,
    filename: str | None = None,
) -> StructuredLoadResult:
    text = decode_text(raw_content)
    lower_name = (filename or "").lower()
    first_non_space = text.lstrip()[:1]
    if lower_name.endswith(".csv"):
        return _csv_records(text)
    if lower_name.endswith((".json", ".jsonl", ".ndjson")) or first_non_space in {"{", "["}:
        return _json_records(text)
    if "," in text.partition("\n")[0]:
        return _csv_records(text)
    return _json_records(text)
