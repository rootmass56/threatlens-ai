from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

CORRELATION_VERSION = "0.8.0"


@dataclass(frozen=True)
class CorrelationPolicy:
    """Deterministic policy controlling advanced incident correlation."""

    window_minutes: int = 30
    deduplication_window_seconds: int = 60
    relationship_threshold: float = 0.66
    evidence_relationship_threshold: float = 0.40
    maximum_incident_span_minutes: int = 60

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_minutes": self.window_minutes,
            "deduplication_window_seconds": self.deduplication_window_seconds,
            "relationship_threshold": self.relationship_threshold,
            "evidence_relationship_threshold": self.evidence_relationship_threshold,
            "maximum_incident_span_minutes": self.maximum_incident_span_minutes,
        }


@dataclass(frozen=True)
class AdvancedCorrelationResult:
    """Complete deterministic output of the v0.8 correlation engine."""

    incidents_df: pd.DataFrame
    deduplicated_alerts_df: pd.DataFrame
    entities_df: pd.DataFrame
    relationships_df: pd.DataFrame
    graph_nodes_df: pd.DataFrame
    graph_edges_df: pd.DataFrame
    metrics: dict[str, Any] = field(default_factory=dict)
    policy: CorrelationPolicy = field(default_factory=CorrelationPolicy)
    version: str = CORRELATION_VERSION

    @classmethod
    def empty(cls, policy: CorrelationPolicy | None = None) -> AdvancedCorrelationResult:
        return cls(
            incidents_df=pd.DataFrame(),
            deduplicated_alerts_df=pd.DataFrame(),
            entities_df=pd.DataFrame(),
            relationships_df=pd.DataFrame(),
            graph_nodes_df=pd.DataFrame(),
            graph_edges_df=pd.DataFrame(),
            metrics={
                "input_alerts": 0,
                "representative_alerts": 0,
                "deduplicated_alerts": 0,
                "duplicate_groups": 0,
                "entities": 0,
                "relationships": 0,
                "cluster_relationships": 0,
                "incidents": 0,
                "graph_nodes": 0,
                "graph_edges": 0,
            },
            policy=policy or CorrelationPolicy(),
        )

    def graph_payload(self) -> dict[str, Any]:
        """Return a JSON-compatible attack graph snapshot."""

        return {
            "schema": "threatlens-attack-graph-1.0",
            "correlation_version": self.version,
            "policy": self.policy.as_dict(),
            "metrics": _json_compatible(self.metrics),
            "nodes": _records(self.graph_nodes_df),
            "edges": _records(self.graph_edges_df),
        }

    def graph_json(self, *, indent: int | None = 2) -> bytes:
        return json.dumps(
            self.graph_payload(),
            indent=indent,
            sort_keys=True,
            separators=None if indent else (",", ":"),
        ).encode("utf-8")

    @property
    def graph_sha256(self) -> str:
        return hashlib.sha256(self.graph_json(indent=None)).hexdigest()

    @classmethod
    def from_persisted(cls, payload: dict[str, Any] | None) -> AdvancedCorrelationResult:
        """Hydrate a correlation result from database-backed records."""

        if not payload:
            return cls.empty()
        policy_values = payload.get("policy") or {}
        policy = CorrelationPolicy(
            window_minutes=int(policy_values.get("window_minutes", 30)),
            deduplication_window_seconds=int(policy_values.get("deduplication_window_seconds", 60)),
            relationship_threshold=float(policy_values.get("relationship_threshold", 0.66)),
            evidence_relationship_threshold=float(
                policy_values.get("evidence_relationship_threshold", 0.40)
            ),
            maximum_incident_span_minutes=int(
                policy_values.get("maximum_incident_span_minutes", 60)
            ),
        )
        graph = payload.get("graph") or {}
        return cls(
            incidents_df=pd.DataFrame(payload.get("incidents") or []),
            deduplicated_alerts_df=pd.DataFrame(payload.get("deduplicated_alerts") or []),
            entities_df=pd.DataFrame(payload.get("entities") or []),
            relationships_df=pd.DataFrame(payload.get("relationships") or []),
            graph_nodes_df=pd.DataFrame(graph.get("nodes") or []),
            graph_edges_df=pd.DataFrame(graph.get("edges") or []),
            metrics=dict(payload.get("metrics") or {}),
            policy=policy,
            version=str(payload.get("version") or CORRELATION_VERSION),
        )


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(item) for item in value]
    if pd.isna(value):
        return None
    return str(value)


def _records(frame: pd.DataFrame) -> list[dict[str, Any]]:
    if frame.empty:
        return []
    return [
        {str(key): _json_compatible(value) for key, value in record.items()}
        for record in frame.to_dict(orient="records")
    ]
