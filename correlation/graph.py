from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

import pandas as pd

from correlation.entities import clean_text
from correlation.stages import normalize_tactic

NODE_COLUMNS = [
    "node_id",
    "label",
    "node_type",
    "subtype",
    "severity",
    "confidence",
    "incident_id",
    "x",
    "y",
    "metadata",
]

EDGE_COLUMNS = [
    "edge_id",
    "source",
    "target",
    "relationship_type",
    "confidence",
    "incident_id",
    "reasons",
    "metadata",
]

_LAYER_X = {
    "incident": 0.0,
    "alert": 1.0,
    "entity": 2.0,
    "technique": 3.0,
    "tactic": 4.0,
}


def _edge_id(source: str, target: str, relationship_type: str) -> str:
    payload = f"{source}|{target}|{relationship_type}".encode()
    return hashlib.sha256(payload).hexdigest()[:20]


def build_attack_graph(
    alerts_df: pd.DataFrame,
    incidents_df: pd.DataFrame,
    entities_df: pd.DataFrame,
    relationships_df: pd.DataFrame,
    dedup_groups_df: pd.DataFrame,
    alert_entities: dict[int, set[str]],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create a deterministic, exportable multi-layer attack graph."""

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    alert_to_incident: dict[int, int] = {}

    for _, incident in incidents_df.iterrows():
        incident_id = int(incident.get("incident_id"))
        node_id = f"incident:{incident_id}"
        nodes[node_id] = {
            "node_id": node_id,
            "label": clean_text(incident.get("incident_name")) or f"Incident {incident_id}",
            "node_type": "incident",
            "subtype": "correlated_case",
            "severity": clean_text(incident.get("severity")),
            "confidence": float(incident.get("confidence") or 0.0),
            "incident_id": incident_id,
            "metadata": {
                "correlation_id": incident.get("correlation_id"),
                "risk_score": int(incident.get("risk_score") or 0),
                "stage_progression": incident.get("stage_progression"),
                "graph_score": float(incident.get("graph_score") or 0.0),
            },
        }
        for alert_id in _int_list(incident.get("alert_ids")):
            alert_to_incident[alert_id] = incident_id

    for _, alert in alerts_df.iterrows():
        try:
            alert_id = int(alert.get("alert_id"))
        except (TypeError, ValueError):
            continue
        incident_id = alert_to_incident.get(alert_id)
        node_id = f"alert:{alert_id}"
        nodes[node_id] = {
            "node_id": node_id,
            "label": clean_text(alert.get("detection_name")) or f"Alert {alert_id}",
            "node_type": "alert",
            "subtype": clean_text(alert.get("source_dataset")) or "detection",
            "severity": clean_text(alert.get("severity")),
            "confidence": float(alert.get("confidence") or 0.0),
            "incident_id": incident_id,
            "metadata": {
                "alert_id": alert_id,
                "rule_id": alert.get("rule_id"),
                "risk_score": int(alert.get("risk_score") or 0),
                "timestamp": alert.get("timestamp"),
                "source_dataset": alert.get("source_dataset"),
                "dedup_group_id": alert.get("dedup_group_id"),
            },
        }
        if incident_id is not None:
            _add_edge(
                edges,
                source=f"incident:{incident_id}",
                target=node_id,
                relationship_type="contains_alert",
                confidence=1.0,
                incident_id=incident_id,
                reasons=["alert is evidence in correlated incident"],
            )

        for entity_key in sorted(alert_entities.get(alert_id, set())):
            _add_edge(
                edges,
                source=node_id,
                target=f"entity:{entity_key}",
                relationship_type="observed_entity",
                confidence=0.92,
                incident_id=incident_id,
                reasons=["entity extracted from alert or supporting event evidence"],
            )

        technique_id = clean_text(alert.get("mitre_technique_id"))
        tactic = normalize_tactic(alert.get("mitre_tactic"))
        if technique_id:
            technique_node = f"technique:{technique_id}"
            nodes.setdefault(
                technique_node,
                {
                    "node_id": technique_node,
                    "label": f"{technique_id} {clean_text(alert.get('mitre_technique'))}".strip(),
                    "node_type": "technique",
                    "subtype": "mitre_attack",
                    "severity": "",
                    "confidence": float(alert.get("confidence") or 0.0),
                    "incident_id": incident_id,
                    "metadata": {"attack_id": technique_id},
                },
            )
            _add_edge(
                edges,
                source=node_id,
                target=technique_node,
                relationship_type="maps_to_technique",
                confidence=float(alert.get("confidence") or 0.0),
                incident_id=incident_id,
                reasons=["validated rule-to-ATT&CK mapping"],
            )
            if tactic != "Unknown":
                tactic_node = f"tactic:{tactic.lower().replace(' ', '-')}"
                nodes.setdefault(
                    tactic_node,
                    {
                        "node_id": tactic_node,
                        "label": tactic,
                        "node_type": "tactic",
                        "subtype": "mitre_attack",
                        "severity": "",
                        "confidence": 1.0,
                        "incident_id": incident_id,
                        "metadata": {"tactic": tactic},
                    },
                )
                _add_edge(
                    edges,
                    source=technique_node,
                    target=tactic_node,
                    relationship_type="belongs_to_tactic",
                    confidence=1.0,
                    incident_id=incident_id,
                    reasons=["official ATT&CK tactic association declared by rule"],
                )

    for _, entity in entities_df.iterrows():
        key = clean_text(entity.get("entity_key"))
        if not key:
            continue
        incident_ids = _int_list(entity.get("incident_ids"))
        incident_id = incident_ids[0] if len(incident_ids) == 1 else None
        node_id = f"entity:{key}"
        nodes[node_id] = {
            "node_id": node_id,
            "label": clean_text(entity.get("display_value")) or key,
            "node_type": "entity",
            "subtype": clean_text(entity.get("entity_type")),
            "severity": "",
            "confidence": float(entity.get("confidence") or 0.0),
            "incident_id": incident_id,
            "metadata": {
                "canonical_value": entity.get("canonical_value"),
                "aliases": entity.get("aliases") or [],
                "source_datasets": entity.get("source_datasets") or [],
                "evidence_alert_ids": entity.get("evidence_alert_ids") or [],
            },
        }

    for _, relationship in relationships_df.iterrows():
        left_id = int(relationship.get("source_alert_id"))
        right_id = int(relationship.get("target_alert_id"))
        incident_ids = _int_list(relationship.get("incident_ids"))
        incident_id = incident_ids[0] if len(incident_ids) == 1 else None
        _add_edge(
            edges,
            source=f"alert:{left_id}",
            target=f"alert:{right_id}",
            relationship_type=clean_text(relationship.get("relationship_type")),
            confidence=float(relationship.get("confidence") or 0.0),
            incident_id=incident_id,
            reasons=relationship.get("reasons") or [],
            metadata={
                "shared_entities": relationship.get("shared_entities") or [],
                "cluster_eligible": bool(relationship.get("cluster_eligible")),
                "time_delta_seconds": relationship.get("time_delta_seconds"),
            },
        )

    if not dedup_groups_df.empty:
        for _, group in dedup_groups_df.iterrows():
            representative = int(group.get("representative_alert_id"))
            members = _int_list(group.get("member_alert_ids"))
            for member in members:
                if member == representative:
                    continue
                _add_edge(
                    edges,
                    source=f"alert:{member}",
                    target=f"alert:{representative}",
                    relationship_type="semantic_duplicate",
                    confidence=0.98,
                    incident_id=alert_to_incident.get(member),
                    reasons=["same technique and resolved entities inside deduplication window"],
                )

    node_rows = list(nodes.values())
    _apply_layout(node_rows)
    return (
        pd.DataFrame(node_rows, columns=NODE_COLUMNS),
        pd.DataFrame(list(edges.values()), columns=EDGE_COLUMNS),
    )


def _add_edge(
    edges: dict[str, dict[str, Any]],
    *,
    source: str,
    target: str,
    relationship_type: str,
    confidence: float,
    incident_id: int | None,
    reasons: list[str] | tuple[str, ...],
    metadata: dict[str, Any] | None = None,
) -> None:
    key = _edge_id(source, target, relationship_type)
    edges[key] = {
        "edge_id": key,
        "source": source,
        "target": target,
        "relationship_type": relationship_type,
        "confidence": round(float(confidence), 3),
        "incident_id": incident_id,
        "reasons": list(reasons),
        "metadata": metadata or {},
    }


def _apply_layout(nodes: list[dict[str, Any]]) -> None:
    layers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        layers[node["node_type"]].append(node)
    for node_type, layer_nodes in layers.items():
        layer_nodes.sort(key=lambda item: (str(item.get("incident_id")), item["label"]))
        total = len(layer_nodes)
        for index, node in enumerate(layer_nodes):
            node["x"] = _LAYER_X.get(node_type, 5.0)
            node["y"] = float(total - index - 1) - ((total - 1) / 2 if total else 0)


def _int_list(value: Any) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        output: list[int] = []
        for item in value:
            try:
                output.append(int(item))
            except (TypeError, ValueError):
                continue
        return output
    if value is None:
        return []
    try:
        if pd.isna(value):
            return []
    except (TypeError, ValueError):
        pass
    text = str(value).strip().strip("[]")
    if not text:
        return []
    return [int(item.strip()) for item in text.split(",") if item.strip().isdigit()]


def graph_to_json(nodes_df: pd.DataFrame, edges_df: pd.DataFrame) -> bytes:
    payload = {
        "schema": "threatlens-attack-graph-1.0",
        "nodes": nodes_df.to_dict(orient="records"),
        "edges": edges_df.to_dict(orient="records"),
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
