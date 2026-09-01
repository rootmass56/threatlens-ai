from pathlib import Path

from core.pipeline import SourceInput, analyze_linux_auth_log, analyze_sources

SAMPLE_DIR = Path("data/sample_logs")


def _multi_source_result():
    names = [
        "windows_security_sample.jsonl",
        "sysmon_sample.jsonl",
        "suricata_eve_sample.jsonl",
        "zeek_conn_sample.log",
        "zeek_dns_sample.log",
    ]
    return analyze_sources(
        [
            SourceInput(
                raw_content=(SAMPLE_DIR / name).read_bytes(),
                filename=name,
            )
            for name in names
        ]
    )


def test_linux_attack_storyline_remains_one_incident():
    result = analyze_linux_auth_log(
        (SAMPLE_DIR / "auth_sample.log").read_text(encoding="utf-8-sig")
    )
    assert result.incident_count == 1
    incident = result.incidents_df.iloc[0]
    assert incident["incident_name"] == "Account Compromise with Privilege Escalation"
    assert incident["alert_count"] == 4
    assert incident["stage_count"] == 3
    assert "Privilege Escalation" in incident["stage_progression"]
    assert result.correlation_result is not None
    assert result.correlation_result.metrics["graph_nodes"] > 0


def test_multi_source_correlation_deduplicates_and_preserves_evidence():
    result = _multi_source_result()
    correlation = result.correlation_result

    assert correlation is not None
    assert result.event_count == 22
    assert result.alert_count == 7
    assert result.incident_count == 2

    expected_metrics = {
        "input_alerts": 7,
        "representative_alerts": 6,
        "deduplicated_alerts": 1,
        "duplicate_groups": 1,
        "entities": 10,
        "relationships": 12,
        "cluster_relationships": 6,
        "incidents": 2,
        "multi_source_incidents": 2,
        "multi_stage_incidents": 2,
        "graph_nodes": 29,
        "graph_edges": 55,
    }
    for key, expected in expected_metrics.items():
        assert correlation.metrics[key] == expected

    assert sorted(
        int(value) for value in result.incidents_df["alert_count"].tolist()
    ) == [3, 4]

    assert len(correlation.deduplicated_alerts_df) == 6
    assert len(correlation.entities_df) == 10
    assert len(correlation.relationships_df) == 12
    assert len(correlation.graph_nodes_df) == 29
    assert len(correlation.graph_edges_df) == 55

    evidence_columns = ['alert_id', 'source_ip', 'source_dataset', 'duplicate_alert_ids', 'duplicate_count']
    assert evidence_columns
    assert all(
        column in correlation.deduplicated_alerts_df.columns
        for column in evidence_columns
    )
    assert correlation.deduplicated_alerts_df[evidence_columns].notna().any().any()

def test_relationships_are_explainable_and_cluster_qualified():
    result = _multi_source_result()
    relationships = result.correlation_result.relationships_df
    assert not relationships.empty
    assert relationships["confidence"].between(0.0, 1.0).all()
    assert relationships["reasons"].map(bool).all()
    cluster_edges = relationships[relationships["cluster_eligible"]]
    assert len(cluster_edges) >= 5
    assert cluster_edges["shared_entity_count"].ge(1).all()


def test_attack_graph_contains_all_required_layers():
    result = _multi_source_result()
    correlation = result.correlation_result
    node_types = set(correlation.graph_nodes_df["node_type"])
    assert {"incident", "alert", "entity", "technique", "tactic"}.issubset(node_types)
    edge_types = set(correlation.graph_edges_df["relationship_type"])
    assert {
        "contains_alert",
        "observed_entity",
        "maps_to_technique",
        "belongs_to_tactic",
    }.issubset(edge_types)
    assert len(correlation.graph_sha256) == 64
    assert correlation.graph_payload()["schema"] == "threatlens-attack-graph-1.0"
