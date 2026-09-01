from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePath, PureWindowsPath
from typing import Any

import pandas as pd

ENTITY_COLUMNS = [
    "entity_key",
    "entity_type",
    "canonical_value",
    "display_value",
    "confidence",
    "aliases",
    "source_datasets",
    "first_seen",
    "last_seen",
    "evidence_alert_ids",
    "evidence_event_ids",
    "incident_ids",
]

_MISSING = {"", "nan", "none", "null", "nat", "<na>"}


@dataclass
class _EntityAccumulator:
    entity_type: str
    canonical_value: str
    display_value: str
    confidence: float = 0.0
    aliases: set[str] = field(default_factory=set)
    source_datasets: set[str] = field(default_factory=set)
    timestamps: list[pd.Timestamp] = field(default_factory=list)
    alert_ids: set[int] = field(default_factory=set)
    event_ids: set[int] = field(default_factory=set)

    def update(
        self,
        *,
        display_value: str,
        confidence: float,
        source_dataset: str | None,
        timestamp: Any,
        alert_id: int,
        event_id: int | None,
    ) -> None:
        self.display_value = self.display_value or display_value
        self.confidence = max(self.confidence, confidence)
        self.aliases.add(display_value)
        if source_dataset:
            self.source_datasets.add(source_dataset)
        parsed = pd.to_datetime(timestamp, errors="coerce", utc=True)
        if not pd.isna(parsed):
            self.timestamps.append(parsed)
        self.alert_ids.add(alert_id)
        if event_id is not None:
            self.event_ids.add(event_id)


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if bool(pd.isna(value)):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    return "" if text.lower() in _MISSING else text


def canonicalize(entity_type: str, value: Any) -> str:
    text = clean_text(value)
    if not text:
        return ""
    if entity_type == "ip":
        try:
            return ipaddress.ip_address(text).compressed.lower()
        except ValueError:
            return text.lower()
    if entity_type == "hostname":
        return text.rstrip(".").lower()
    if entity_type == "username":
        return re.sub(r"\s+", "", text).lower()
    if entity_type == "process":
        normalized = text.replace("/", "\\")
        try:
            return PureWindowsPath(normalized).name.lower()
        except (TypeError, ValueError):
            return PurePath(text).name.lower()
    if entity_type in {"domain", "url"}:
        return text.rstrip(".").lower()
    if entity_type == "file":
        return text.replace("/", "\\").lower()
    if entity_type == "hash":
        return text.lower()
    return text.lower()


def entity_key(entity_type: str, canonical_value: str) -> str:
    return f"{entity_type}:{canonical_value}"


def _int_values(value: Any) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        output: list[int] = []
        for item in value:
            try:
                output.append(int(item))
            except (TypeError, ValueError):
                continue
        return output
    text = clean_text(value)
    if not text:
        return []
    output = []
    for item in text.strip("[]").split(","):
        try:
            output.append(int(item.strip()))
        except ValueError:
            continue
    return output


class EntityResolver:
    """Resolve canonical entities from alerts and supporting normalized events."""

    DIRECT_FIELDS = (
        ("source_ip", "ip", 0.98),
        ("username", "username", 0.96),
        ("hostname", "hostname", 0.96),
        ("destination_ip", "ip", 0.90),
        ("process_name", "process", 0.88),
        ("domain", "domain", 0.88),
    )
    EVENT_FIELDS = (
        ("source_ip", "ip", 0.94),
        ("destination_ip", "ip", 0.92),
        ("username", "username", 0.92),
        ("hostname", "hostname", 0.92),
        ("process_name", "process", 0.86),
        ("parent_process_name", "process", 0.82),
        ("domain", "domain", 0.88),
        ("file_path", "file", 0.84),
        ("url", "url", 0.82),
    )

    def resolve(
        self,
        alerts_df: pd.DataFrame,
        events_df: pd.DataFrame | None = None,
    ) -> tuple[pd.DataFrame, dict[int, set[str]]]:
        if alerts_df.empty:
            return pd.DataFrame(columns=ENTITY_COLUMNS), {}

        event_lookup: dict[int, pd.Series] = {}
        if events_df is not None and not events_df.empty and "event_id" in events_df.columns:
            for _, event in events_df.iterrows():
                try:
                    event_lookup[int(event.get("event_id"))] = event
                except (TypeError, ValueError):
                    continue

        accumulators: dict[str, _EntityAccumulator] = {}
        alert_entities: dict[int, set[str]] = defaultdict(set)

        for _, alert in alerts_df.iterrows():
            try:
                alert_id = int(alert.get("alert_id"))
            except (TypeError, ValueError):
                continue
            source_dataset = clean_text(alert.get("source_dataset")) or None
            timestamp = alert.get("timestamp")

            for field_name, entity_type, confidence in self.DIRECT_FIELDS:
                self._record(
                    accumulators,
                    alert_entities,
                    alert_id=alert_id,
                    event_id=None,
                    entity_type=entity_type,
                    value=alert.get(field_name),
                    confidence=confidence,
                    source_dataset=source_dataset,
                    timestamp=timestamp,
                )

            event_ids = set(_int_values(alert.get("supporting_event_ids")))
            try:
                event_ids.add(int(alert.get("event_id")))
            except (TypeError, ValueError):
                pass
            for event_id in sorted(event_ids):
                event = event_lookup.get(event_id)
                if event is None:
                    continue
                dataset = clean_text(event.get("source_dataset")) or source_dataset
                event_timestamp = event.get("timestamp") or timestamp
                for field_name, entity_type, confidence in self.EVENT_FIELDS:
                    self._record(
                        accumulators,
                        alert_entities,
                        alert_id=alert_id,
                        event_id=event_id,
                        entity_type=entity_type,
                        value=event.get(field_name),
                        confidence=confidence,
                        source_dataset=dataset,
                        timestamp=event_timestamp,
                    )
                attributes = event.get("attributes")
                if isinstance(attributes, dict):
                    for key in ("sha256", "file_sha256", "hash", "md5"):
                        self._record(
                            accumulators,
                            alert_entities,
                            alert_id=alert_id,
                            event_id=event_id,
                            entity_type="hash",
                            value=attributes.get(key),
                            confidence=0.96,
                            source_dataset=dataset,
                            timestamp=event_timestamp,
                        )

        rows: list[dict[str, Any]] = []
        for key, item in sorted(accumulators.items()):
            rows.append(
                {
                    "entity_key": key,
                    "entity_type": item.entity_type,
                    "canonical_value": item.canonical_value,
                    "display_value": item.display_value,
                    "confidence": round(item.confidence, 3),
                    "aliases": sorted(item.aliases),
                    "source_datasets": sorted(item.source_datasets),
                    "first_seen": min(item.timestamps).isoformat() if item.timestamps else None,
                    "last_seen": max(item.timestamps).isoformat() if item.timestamps else None,
                    "evidence_alert_ids": sorted(item.alert_ids),
                    "evidence_event_ids": sorted(item.event_ids),
                    "incident_ids": [],
                }
            )
        return pd.DataFrame(rows, columns=ENTITY_COLUMNS), dict(alert_entities)

    @staticmethod
    def _record(
        accumulators: dict[str, _EntityAccumulator],
        alert_entities: dict[int, set[str]],
        *,
        alert_id: int,
        event_id: int | None,
        entity_type: str,
        value: Any,
        confidence: float,
        source_dataset: str | None,
        timestamp: Any,
    ) -> None:
        display = clean_text(value)
        canonical = canonicalize(entity_type, display)
        if not canonical:
            return
        key = entity_key(entity_type, canonical)
        item = accumulators.setdefault(
            key,
            _EntityAccumulator(
                entity_type=entity_type,
                canonical_value=canonical,
                display_value=display,
            ),
        )
        item.update(
            display_value=display,
            confidence=confidence,
            source_dataset=source_dataset,
            timestamp=timestamp,
            alert_id=alert_id,
            event_id=event_id,
        )
        alert_entities[alert_id].add(key)
