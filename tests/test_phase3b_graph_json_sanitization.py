import json

import pandas as pd

from correlation.models import AdvancedCorrelationResult


def test_graph_payload_sanitizes_non_finite_values_for_strict_json() -> None:
    result = AdvancedCorrelationResult(
        incidents_df=pd.DataFrame(),
        deduplicated_alerts_df=pd.DataFrame(),
        entities_df=pd.DataFrame(),
        relationships_df=pd.DataFrame(),
        graph_nodes_df=pd.DataFrame(
            [
                {
                    "node_id": "alert:1",
                    "node_type": "alert",
                    "confidence": 0.98,
                    "incident_id": float("nan"),
                    "positive_infinity": float("inf"),
                }
            ]
        ),
        graph_edges_df=pd.DataFrame(
            [
                {
                    "source": "alert:1",
                    "target": "entity:ip:10.0.0.1",
                    "negative_infinity": float("-inf"),
                }
            ]
        ),
        metrics={"nullable_metric": float("nan")},
    )

    payload = result.graph_payload()

    assert payload["metrics"]["nullable_metric"] is None
    assert payload["nodes"][0]["incident_id"] is None
    assert payload["nodes"][0]["positive_infinity"] is None
    assert payload["edges"][0]["negative_infinity"] is None

    # PostgreSQL JSON accepts strict RFC-compatible null values, not NaN/Infinity.
    encoded = json.dumps(payload, allow_nan=False)
    assert "NaN" not in encoded
    assert "Infinity" not in encoded

    graph_bytes = result.graph_json(indent=None)
    assert b"NaN" not in graph_bytes
    assert b"Infinity" not in graph_bytes