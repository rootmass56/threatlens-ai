from __future__ import annotations

import json

import pandas as pd

from correlation.models import AdvancedCorrelationResult


def _reject_nonstandard(token: str) -> None:
    raise ValueError(token)


def test_persisted_graph_payload_is_strict_json_safe() -> None:
    result = AdvancedCorrelationResult(
        incidents_df=pd.DataFrame(),
        deduplicated_alerts_df=pd.DataFrame(),
        entities_df=pd.DataFrame(),
        relationships_df=pd.DataFrame(),
        graph_nodes_df=pd.DataFrame(
            [
                {"node_id": "incident:1", "incident_id": 1, "confidence": 1.0},
                {"node_id": "tactic:test", "incident_id": None, "confidence": 0.96},
            ]
        ),
        graph_edges_df=pd.DataFrame(
            [
                {
                    "edge_id": "edge:test",
                    "incident_id": None,
                    "confidence": float("inf"),
                }
            ]
        ),
        metrics={"score": float("nan")},
    )

    payload = result.graph_payload()

    assert payload["nodes"][1]["incident_id"] is None
    assert payload["edges"][0]["incident_id"] is None
    assert payload["edges"][0]["confidence"] is None
    assert payload["metrics"]["score"] is None

    strict = json.dumps(payload, allow_nan=False)
    assert "NaN" not in strict
    assert "Infinity" not in strict
    json.loads(strict, parse_constant=_reject_nonstandard)

    serialized = result.graph_json(indent=None)
    assert b"NaN" not in serialized
    assert b"Infinity" not in serialized