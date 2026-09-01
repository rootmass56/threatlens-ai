from __future__ import annotations

import hashlib
from collections import defaultdict
from itertools import combinations
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pandas as pd

from core.risk_scoring import risk_level
from correlation.deduplication import DeduplicationResult, deduplicate_alerts
from correlation.entities import ENTITY_COLUMNS, EntityResolver, clean_text
from correlation.graph import build_attack_graph
from correlation.models import AdvancedCorrelationResult, CorrelationPolicy
from correlation.scoring import score_alert_relationship
from correlation.stages import ordered_stage_sequence

INCIDENT_COLUMNS = [
    "incident_id",
    "correlation_id",
    "correlation_version",
    "incident_name",
    "source_ip",
    "severity",
    "risk_score",
    "confidence",
    "status",
    "summary",
    "storyline",
    "start_time",
    "end_time",
    "alert_count",
    "representative_alert_count",
    "deduplicated_alert_count",
    "source_count",
    "entity_count",
    "relationship_count",
    "stage_count",
    "stage_progression",
    "graph_score",
    "detections",
    "alert_ids",
    "entities",
]

RELATIONSHIP_COLUMNS = [
    "relationship_id",
    "source_alert_id",
    "target_alert_id",
    "relationship_type",
    "confidence",
    "reasons",
    "shared_entities",
    "shared_entity_count",
    "shared_source_ip",
    "same_technique",
    "time_delta_seconds",
    "cluster_eligible",
    "incident_ids",
]


def advanced_correlate_alerts(
    alerts_df: pd.DataFrame,
    events_df: pd.DataFrame | None = None,
    *,
    policy: CorrelationPolicy | None = None,
) -> AdvancedCorrelationResult:
    """Correlate alerts using entities, ATT&CK stages, time and source corroboration."""

    active_policy = policy or CorrelationPolicy()
    if alerts_df.empty:
        return AdvancedCorrelationResult.empty(active_policy)

    enriched_alerts = _enrich_alerts(alerts_df, events_df)
    deduplication = deduplicate_alerts(
        enriched_alerts,
        window_seconds=active_policy.deduplication_window_seconds,
    )
    resolver = EntityResolver()
    entities_df, alert_entities = resolver.resolve(enriched_alerts, events_df)
    representatives = deduplication.representatives.copy()

    relationships = _score_relationships(
        representatives,
        alert_entities,
        policy=active_policy,
    )
    relationships_df = pd.DataFrame(relationships, columns=RELATIONSHIP_COLUMNS)
    components = _connected_components(
        representatives,
        relationships_df,
        maximum_span_minutes=active_policy.maximum_incident_span_minutes,
    )
    incidents_df = _build_incidents(
        components,
        representatives,
        enriched_alerts,
        entities_df,
        alert_entities,
        relationships_df,
        deduplication,
    )
    entities_df, relationships_df = _assign_incident_membership(
        incidents_df,
        entities_df,
        relationships_df,
        alert_entities,
    )
    graph_nodes_df, graph_edges_df = build_attack_graph(
        enriched_alerts,
        incidents_df,
        entities_df,
        relationships_df,
        deduplication.groups,
        alert_entities,
    )
    metrics = {
        "input_alerts": len(enriched_alerts),
        "representative_alerts": len(representatives),
        "deduplicated_alerts": deduplication.deduplicated_alerts,
        "duplicate_groups": deduplication.duplicate_groups,
        "entities": len(entities_df),
        "relationships": len(relationships_df),
        "cluster_relationships": int(
            relationships_df.get("cluster_eligible", pd.Series(dtype=bool)).sum()
        ),
        "incidents": len(incidents_df),
        "graph_nodes": len(graph_nodes_df),
        "graph_edges": len(graph_edges_df),
        "multi_source_incidents": int(
            (incidents_df.get("source_count", pd.Series(dtype=int)) > 1).sum()
        ),
        "multi_stage_incidents": int(
            (incidents_df.get("stage_count", pd.Series(dtype=int)) > 1).sum()
        ),
    }
    return AdvancedCorrelationResult(
        incidents_df=incidents_df,
        deduplicated_alerts_df=representatives,
        entities_df=entities_df,
        relationships_df=relationships_df,
        graph_nodes_df=graph_nodes_df,
        graph_edges_df=graph_edges_df,
        metrics=metrics,
        policy=active_policy,
    )


def correlate_alerts(
    alerts_df: pd.DataFrame,
    *,
    window_minutes: int = 30,
    events_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Backward-compatible incident DataFrame entry point."""

    return advanced_correlate_alerts(
        alerts_df,
        events_df,
        policy=CorrelationPolicy(window_minutes=window_minutes),
    ).incidents_df


def _enrich_alerts(
    alerts_df: pd.DataFrame,
    events_df: pd.DataFrame | None,
) -> pd.DataFrame:
    frame = alerts_df.copy()
    defaults = {
        "source_dataset": "",
        "connector_id": "",
        "destination_ip": "",
        "process_name": "",
        "domain": "",
    }
    if events_df is None or events_df.empty or "event_id" not in events_df.columns:
        for column, default in defaults.items():
            if column not in frame.columns:
                frame[column] = default
        return frame

    lookup: dict[int, pd.Series] = {}
    for _, event in events_df.iterrows():
        try:
            lookup[int(event.get("event_id"))] = event
        except (TypeError, ValueError):
            continue
    for column in defaults:
        if column not in frame.columns:
            frame[column] = ""
    for index, alert in frame.iterrows():
        try:
            event = lookup.get(int(alert.get("event_id")))
        except (TypeError, ValueError):
            event = None
        if event is None:
            continue
        for column in defaults:
            if not clean_text(frame.at[index, column]):
                frame.at[index, column] = event.get(column)
    return frame


def _score_relationships(
    representatives: pd.DataFrame,
    alert_entities: dict[int, set[str]],
    *,
    policy: CorrelationPolicy,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    records = [row for _, row in representatives.iterrows()]
    for left, right in combinations(records, 2):
        left_id = int(left.get("alert_id"))
        right_id = int(right.get("alert_id"))
        score = score_alert_relationship(
            left,
            right,
            alert_entities.get(left_id, set()),
            alert_entities.get(right_id, set()),
            threshold=policy.relationship_threshold,
            window_minutes=policy.window_minutes,
        )
        if score.confidence < policy.evidence_relationship_threshold:
            continue
        relationship_id = hashlib.sha256(
            f"{left_id}|{right_id}|{score.relationship_type}".encode()
        ).hexdigest()[:20]
        rows.append(
            {
                "relationship_id": relationship_id,
                "source_alert_id": left_id,
                "target_alert_id": right_id,
                "relationship_type": score.relationship_type,
                "confidence": score.confidence,
                "reasons": list(score.reasons),
                "shared_entities": list(score.shared_entities),
                "shared_entity_count": score.shared_entity_count,
                "shared_source_ip": score.shared_source_ip,
                "same_technique": score.same_technique,
                "time_delta_seconds": score.time_delta_seconds,
                "cluster_eligible": score.cluster_eligible,
                "incident_ids": [],
            }
        )
    return rows


def _connected_components(
    representatives: pd.DataFrame,
    relationships_df: pd.DataFrame,
    *,
    maximum_span_minutes: int,
) -> list[set[int]]:
    alert_ids = {int(value) for value in representatives["alert_id"].tolist()}
    adjacency: dict[int, set[int]] = {alert_id: set() for alert_id in alert_ids}
    if not relationships_df.empty:
        for _, relation in relationships_df.iterrows():
            if not bool(relation.get("cluster_eligible")):
                continue
            left = int(relation.get("source_alert_id"))
            right = int(relation.get("target_alert_id"))
            adjacency[left].add(right)
            adjacency[right].add(left)

    components: list[set[int]] = []
    remaining = set(alert_ids)
    while remaining:
        start = min(remaining)
        stack = [start]
        component: set[int] = set()
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            stack.extend(sorted(adjacency[current] - component, reverse=True))
        remaining -= component
        components.extend(
            _split_component_by_span(
                component,
                representatives,
                maximum_span_minutes=maximum_span_minutes,
            )
        )
    return sorted(components, key=lambda item: min(item))


def _split_component_by_span(
    component: set[int],
    representatives: pd.DataFrame,
    *,
    maximum_span_minutes: int,
) -> list[set[int]]:
    subset = representatives[representatives["alert_id"].isin(component)].copy()
    subset["_timestamp"] = pd.to_datetime(subset["timestamp"], errors="coerce", utc=True)
    subset = subset.sort_values("_timestamp", na_position="last")
    chunks: list[set[int]] = []
    current: set[int] = set()
    chunk_start: pd.Timestamp | None = None
    for _, row in subset.iterrows():
        timestamp = row.get("_timestamp")
        if (
            current
            and chunk_start is not None
            and timestamp is not None
            and not pd.isna(timestamp)
            and timestamp - chunk_start > pd.Timedelta(minutes=maximum_span_minutes)
        ):
            chunks.append(current)
            current = set()
            chunk_start = None
        current.add(int(row.get("alert_id")))
        if chunk_start is None and timestamp is not None and not pd.isna(timestamp):
            chunk_start = timestamp
    if current:
        chunks.append(current)
    return chunks or [component]


def _build_incidents(
    components: list[set[int]],
    representatives: pd.DataFrame,
    all_alerts: pd.DataFrame,
    entities_df: pd.DataFrame,
    alert_entities: dict[int, set[str]],
    relationships_df: pd.DataFrame,
    deduplication: DeduplicationResult,
) -> pd.DataFrame:
    group_lookup = {
        int(row.get("representative_alert_id")): _int_list(row.get("member_alert_ids"))
        for _, row in deduplication.groups.iterrows()
    }
    incidents: list[dict[str, Any]] = []
    for incident_id, component in enumerate(components, start=1):
        representative_frame = representatives[representatives["alert_id"].isin(component)].copy()
        original_ids = sorted(
            {
                alert_id
                for representative_id in component
                for alert_id in group_lookup.get(representative_id, [representative_id])
            }
        )
        alert_frame = all_alerts[all_alerts["alert_id"].isin(original_ids)].copy()
        component_entities = set().union(
            *(alert_entities.get(alert_id, set()) for alert_id in original_ids)
        )
        relationship_frame = relationships_df[
            relationships_df["source_alert_id"].isin(component)
            & relationships_df["target_alert_id"].isin(component)
        ]
        stages = ordered_stage_sequence(representative_frame)
        datasets = sorted(
            {
                clean_text(value)
                for value in alert_frame.get("source_dataset", pd.Series(dtype=object))
                if clean_text(value)
            }
        )
        max_risk = int(alert_frame["risk_score"].max())
        risk_score = min(
            max_risk + max(len(stages) - 1, 0) * 3 + max(len(datasets) - 1, 0) * 2,
            100,
        )
        relationship_confidence = (
            float(relationship_frame["confidence"].mean()) if not relationship_frame.empty else 0.0
        )
        alert_confidence = float(alert_frame["confidence"].max())
        confidence = round(min(0.55 * alert_confidence + 0.45 * relationship_confidence, 1.0), 3)
        graph_score = round(
            min(
                (risk_score / 100) * 0.45
                + min(len(component_entities) / 8, 1.0) * 0.15
                + min(len(relationship_frame) / max(len(component), 1), 1.0) * 0.20
                + min(len(stages) / 4, 1.0) * 0.10
                + min(len(datasets) / 3, 1.0) * 0.10,
                1.0,
            ),
            3,
        )
        detections = sorted(set(alert_frame["detection_name"].astype(str)))
        source_ips = sorted(
            {
                clean_text(value)
                for value in alert_frame.get("source_ip", pd.Series(dtype=object))
                if clean_text(value)
            }
        )
        name = _incident_name(stages, detections)
        stage_text = " → ".join(stages) if stages else "No ordered ATT&CK stages"
        storyline = _storyline(
            name=name,
            stage_text=stage_text,
            datasets=datasets,
            detections=detections,
            entity_count=len(component_entities),
            relationship_count=len(relationship_frame),
        )
        correlation_seed = "|".join(str(item) for item in original_ids)
        correlation_id = str(uuid5(NAMESPACE_URL, f"threatlens-v08:{correlation_seed}"))
        entity_summary = _entity_summary(component_entities, entities_df)
        incidents.append(
            {
                "incident_id": incident_id,
                "correlation_id": correlation_id,
                "correlation_version": "0.8.0",
                "incident_name": name,
                "source_ip": ", ".join(source_ips) if source_ips else "unknown",
                "severity": risk_level(risk_score),
                "risk_score": risk_score,
                "confidence": confidence,
                "status": "Open",
                "summary": (
                    f"{name}. Correlated {len(original_ids)} alerts into "
                    f"{len(component)} representative signals across {len(datasets)} "
                    f"telemetry source(s). ATT&CK path: {stage_text}. "
                    f"Graph confidence: {graph_score:.2f}."
                ),
                "storyline": storyline,
                "start_time": alert_frame["timestamp"].min(),
                "end_time": alert_frame["timestamp"].max(),
                "alert_count": len(original_ids),
                "representative_alert_count": len(component),
                "deduplicated_alert_count": len(original_ids) - len(component),
                "source_count": len(datasets),
                "entity_count": len(component_entities),
                "relationship_count": len(relationship_frame),
                "stage_count": len(stages),
                "stage_progression": stage_text,
                "graph_score": graph_score,
                "detections": ", ".join(detections),
                "alert_ids": original_ids,
                "entities": entity_summary,
            }
        )
    return pd.DataFrame(incidents, columns=INCIDENT_COLUMNS)


def _assign_incident_membership(
    incidents_df: pd.DataFrame,
    entities_df: pd.DataFrame,
    relationships_df: pd.DataFrame,
    alert_entities: dict[int, set[str]],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    entity_incidents: dict[str, set[int]] = defaultdict(set)
    alert_incident: dict[int, int] = {}
    for _, incident in incidents_df.iterrows():
        incident_id = int(incident.get("incident_id"))
        for alert_id in _int_list(incident.get("alert_ids")):
            alert_incident[alert_id] = incident_id
            for key in alert_entities.get(alert_id, set()):
                entity_incidents[key].add(incident_id)
    if entities_df.empty:
        entities_df = pd.DataFrame(columns=ENTITY_COLUMNS)
    else:
        entities_df = entities_df.copy()
        entities_df["incident_ids"] = entities_df["entity_key"].map(
            lambda key: sorted(entity_incidents.get(str(key), set()))
        )
    if not relationships_df.empty:
        relationships_df = relationships_df.copy()
        relationships_df["incident_ids"] = relationships_df.apply(
            lambda row: sorted(
                {
                    alert_incident.get(int(row["source_alert_id"])),
                    alert_incident.get(int(row["target_alert_id"])),
                }
                - {None}
            ),
            axis=1,
        )
    return entities_df, relationships_df


def _entity_summary(keys: set[str], entities_df: pd.DataFrame) -> dict[str, list[str]]:
    summary: dict[str, list[str]] = defaultdict(list)
    if entities_df.empty:
        return {}
    indexed = entities_df.set_index("entity_key", drop=False)
    for key in sorted(keys):
        if key not in indexed.index:
            continue
        row = indexed.loc[key]
        summary[str(row.get("entity_type"))].append(str(row.get("display_value")))
    return {key: sorted(set(values)) for key, values in sorted(summary.items())}


def _incident_name(stages: list[str], detections: list[str]) -> str:
    stage_set = set(stages)
    detection_set = set(detections)
    if {"Credential Access", "Execution"}.issubset(stage_set):
        return "Credential Attack with Suspicious Execution"
    if {"Discovery", "Command and Control"}.issubset(stage_set):
        return "Reconnaissance Followed by Command and Control"
    if {"Credential Access", "Privilege Escalation"}.issubset(stage_set):
        return "Account Compromise with Privilege Escalation"
    if {
        "successful_login_after_failures",
        "suspicious_sudo_command",
    }.issubset(detection_set):
        return "Account Compromise with Privilege Escalation"
    if "successful_login_after_failures" in detection_set:
        return "Possible Account Compromise"
    if "multiple_failed_logins" in detection_set or "windows_failed_logons" in detection_set:
        return "Possible Brute Force Attack"
    if "suspicious_sudo_command" in detection_set:
        return "Possible Privilege Misuse"
    if stages:
        return f"Multi-Stage {stages[-1]} Activity"
    return "Suspicious Security Activity"


def _storyline(
    *,
    name: str,
    stage_text: str,
    datasets: list[str],
    detections: list[str],
    entity_count: int,
    relationship_count: int,
) -> str:
    dataset_text = ", ".join(datasets) if datasets else "unknown telemetry"
    return (
        f"{name}: evidence from {dataset_text} resolves {entity_count} entities and "
        f"{relationship_count} scored relationships. Ordered ATT&CK stages: {stage_text}. "
        f"Contributing detections: {', '.join(detections)}."
    )


def _int_list(value: Any) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        output: list[int] = []
        for item in value:
            try:
                output.append(int(item))
            except (TypeError, ValueError):
                continue
        return output
    text = clean_text(value).strip("[]")
    if not text:
        return []
    output = []
    for item in text.split(","):
        try:
            output.append(int(item.strip()))
        except ValueError:
            continue
    return output
