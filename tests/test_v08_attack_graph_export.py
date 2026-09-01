from __future__ import annotations

import json
from pathlib import Path

from core.pipeline import SourceInput, analyze_sources
from correlation.export import (
    EXPORT_SCHEMA,
    GRAPH_SHA256_SCOPE,
    attack_graph_export_json,
)

SAMPLE_DIR = Path("data/sample_logs")


def _reject_non_standard_constant(token: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {token}")


def test_attack_graph_export_normalizes_non_finite_values_and_adds_provenance():
    graph = {
        "schema": "threatlens-attack-graph-1.0",
        "nodes": [{"node_id": "entity:test", "incident_id": float("nan")}],
        "edges": [{"edge_id": "edge:test", "confidence": float("inf")}],
    }

    exported = attack_graph_export_json(
        graph,
        session_uuid="session-test",
        correlation_uuid="correlation-test",
        graph_sha256="a" * 64,
    )

    assert b"NaN" not in exported
    assert b"Infinity" not in exported
    payload = json.loads(exported, parse_constant=_reject_non_standard_constant)
    assert payload["export_schema"] == EXPORT_SCHEMA
    assert payload["session_uuid"] == "session-test"
    assert payload["correlation_uuid"] == "correlation-test"
    assert payload["graph_sha256"] == "a" * 64
    assert payload["graph_sha256_scope"] == GRAPH_SHA256_SCOPE
    assert payload["nodes"][0]["incident_id"] is None
    assert payload["edges"][0]["confidence"] is None


def test_real_multi_source_graph_export_is_strict_and_complete():
    names = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    pipeline = analyze_sources(
        [
            SourceInput(
                raw_content=(SAMPLE_DIR / name).read_bytes(),
                filename=name,
            )
            for name in names
        ]
    )
    correlation = pipeline.correlation_result
    assert correlation is not None

    exported = attack_graph_export_json(
        correlation.graph_payload(),
        session_uuid="session-integration",
        correlation_uuid="correlation-integration",
        graph_sha256=correlation.graph_sha256,
    )
    payload = json.loads(exported, parse_constant=_reject_non_standard_constant)

    assert payload["schema"] == "threatlens-attack-graph-1.0"
    assert payload["correlation_version"] == "0.8.0"
    assert payload["metrics"]["graph_nodes"] == 29
    assert payload["metrics"]["graph_edges"] == 55
    assert len(payload["nodes"]) == 29
    assert len(payload["edges"]) == 55
    assert len(payload["graph_sha256"]) == 64
