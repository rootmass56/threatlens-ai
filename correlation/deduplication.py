from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pandas as pd

from correlation.entities import clean_text


@dataclass(frozen=True)
class DeduplicationResult:
    representatives: pd.DataFrame
    groups: pd.DataFrame
    input_alerts: int
    deduplicated_alerts: int
    duplicate_groups: int


def _semantic_identity(row: pd.Series) -> tuple[str, ...]:
    return (
        clean_text(row.get("mitre_technique_id")).lower(),
        clean_text(row.get("hostname")).lower(),
        clean_text(row.get("username")).lower(),
        clean_text(row.get("source_ip")).lower(),
        clean_text(row.get("destination_ip")).lower(),
    )


def _group_id(identity: tuple[str, ...], index: int) -> str:
    digest = hashlib.sha256("|".join(identity).encode("utf-8")).hexdigest()[:12]
    return f"dedup-{digest}-{index:03d}"


def deduplicate_alerts(
    alerts_df: pd.DataFrame,
    *,
    window_seconds: int = 60,
) -> DeduplicationResult:
    """Collapse semantically equivalent near-simultaneous alerts for correlation only."""

    if alerts_df.empty:
        return DeduplicationResult(
            representatives=alerts_df.copy(),
            groups=pd.DataFrame(),
            input_alerts=0,
            deduplicated_alerts=0,
            duplicate_groups=0,
        )

    frame = alerts_df.copy()
    frame["_timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame = frame.sort_values(["_timestamp", "alert_id"], na_position="last")
    grouped_rows: list[dict[str, Any]] = []
    representative_rows: list[pd.Series] = []
    group_index = 1

    for identity, identity_frame in frame.groupby(
        frame.apply(_semantic_identity, axis=1), sort=False
    ):
        current: list[pd.Series] = []
        last_timestamp: pd.Timestamp | None = None
        for _, row in identity_frame.iterrows():
            timestamp = row.get("_timestamp")
            if (
                current
                and last_timestamp is not None
                and timestamp is not None
                and not pd.isna(timestamp)
                and timestamp - last_timestamp > pd.Timedelta(seconds=window_seconds)
            ):
                _append_group(
                    current,
                    identity,
                    group_index,
                    grouped_rows,
                    representative_rows,
                )
                group_index += 1
                current = []
            current.append(row)
            if timestamp is not None and not pd.isna(timestamp):
                last_timestamp = timestamp
        if current:
            _append_group(
                current,
                identity,
                group_index,
                grouped_rows,
                representative_rows,
            )
            group_index += 1

    representatives = pd.DataFrame(representative_rows).drop(columns=["_timestamp"])
    groups = pd.DataFrame(grouped_rows)
    duplicates = int(sum(max(int(item["member_count"]) - 1, 0) for item in grouped_rows))
    duplicate_groups = int(sum(int(item["member_count"]) > 1 for item in grouped_rows))
    return DeduplicationResult(
        representatives=representatives.reset_index(drop=True),
        groups=groups,
        input_alerts=len(alerts_df),
        deduplicated_alerts=duplicates,
        duplicate_groups=duplicate_groups,
    )


def _append_group(
    rows: list[pd.Series],
    identity: tuple[str, ...],
    group_index: int,
    grouped_rows: list[dict[str, Any]],
    representative_rows: list[pd.Series],
) -> None:
    ranked = sorted(
        rows,
        key=lambda item: (
            -int(item.get("risk_score") or 0),
            -float(item.get("confidence") or 0.0),
            int(item.get("alert_id") or 0),
        ),
    )
    representative = ranked[0].copy()
    member_ids = sorted(int(item.get("alert_id")) for item in rows)
    group_id = _group_id(identity, group_index)
    representative["dedup_group_id"] = group_id
    representative["duplicate_alert_ids"] = member_ids
    representative["duplicate_count"] = max(len(member_ids) - 1, 0)
    representative["corroborating_rules"] = sorted(
        {
            clean_text(item.get("detection_name"))
            for item in rows
            if clean_text(item.get("detection_name"))
        }
    )
    representative["corroborating_datasets"] = sorted(
        {
            clean_text(item.get("source_dataset"))
            for item in rows
            if clean_text(item.get("source_dataset"))
        }
    )
    representative_rows.append(representative)
    timestamps = [
        item.get("_timestamp")
        for item in rows
        if item.get("_timestamp") is not None and not pd.isna(item.get("_timestamp"))
    ]
    grouped_rows.append(
        {
            "dedup_group_id": group_id,
            "representative_alert_id": int(representative.get("alert_id")),
            "member_alert_ids": member_ids,
            "member_count": len(member_ids),
            "technique_id": identity[0] or None,
            "hostname": identity[1] or None,
            "username": identity[2] or None,
            "source_ip": identity[3] or None,
            "destination_ip": identity[4] or None,
            "first_seen": min(timestamps).isoformat() if timestamps else None,
            "last_seen": max(timestamps).isoformat() if timestamps else None,
        }
    )
