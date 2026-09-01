from __future__ import annotations

import json
import math
from collections.abc import Mapping
from datetime import date, datetime
from numbers import Integral, Real
from typing import Any
from uuid import UUID

import pandas as pd

EXPORT_SCHEMA = "threatlens-attack-graph-export-1.0"
GRAPH_SHA256_SCOPE = "persisted_core_graph_payload"


def attack_graph_export_payload(
    graph: Mapping[str, Any],
    *,
    session_uuid: str,
    correlation_uuid: str | None,
    graph_sha256: str | None,
) -> dict[str, Any]:
    """Build a standards-compliant, provenance-rich attack-graph export package."""

    payload = dict(graph)
    payload.update(
        {
            "export_schema": EXPORT_SCHEMA,
            "session_uuid": str(session_uuid),
            "correlation_uuid": str(correlation_uuid) if correlation_uuid else None,
            "graph_sha256": str(graph_sha256) if graph_sha256 else None,
            "graph_sha256_scope": GRAPH_SHA256_SCOPE,
        }
    )
    compatible = _json_compatible(payload)
    if not isinstance(compatible, dict):
        raise TypeError("Attack-graph export payload must be a JSON object.")
    return compatible


def attack_graph_export_json(
    graph: Mapping[str, Any],
    *,
    session_uuid: str,
    correlation_uuid: str | None,
    graph_sha256: str | None,
    indent: int | None = 2,
) -> bytes:
    """Serialize an attack graph as strict RFC-compatible JSON.

    Non-finite floating-point values and missing pandas values are normalized to
    JSON null. ``allow_nan=False`` prevents accidental emission of NaN or Infinity.
    """

    payload = attack_graph_export_payload(
        graph,
        session_uuid=session_uuid,
        correlation_uuid=correlation_uuid,
        graph_sha256=graph_sha256,
    )
    return json.dumps(
        payload,
        indent=indent,
        sort_keys=True,
        separators=None if indent else (",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, Real):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, (pd.Timestamp, datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(item) for item in value]

    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        missing = False
    if isinstance(missing, bool) and missing:
        return None

    item_method = getattr(value, "item", None)
    if callable(item_method):
        try:
            return _json_compatible(item_method())
        except (TypeError, ValueError):
            pass
    return str(value)
