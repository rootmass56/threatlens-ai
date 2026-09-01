from __future__ import annotations

import json
from pathlib import Path

from core.pipeline import SourceInput, analyze_linux_auth_log, analyze_sources

SAMPLE_DIR = Path("data/sample_logs")


def _multi_source_pipeline():
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


def build_report() -> dict:
    linux = analyze_linux_auth_log((SAMPLE_DIR / "auth_sample.log").read_text(encoding="utf-8-sig"))
    multi = _multi_source_pipeline()
    linux_correlation = linux.correlation_result
    multi_correlation = multi.correlation_result
    if linux_correlation is None or multi_correlation is None:
        raise RuntimeError("Advanced correlation output is missing.")

    node_types = set(multi_correlation.graph_nodes_df["node_type"])
    edge_types = set(multi_correlation.graph_edges_df["relationship_type"])
    checks = {
        "linux_regression": (
            linux.event_count,
            linux.alert_count,
            linux.incident_count,
            linux.quarantined_count,
        )
        == (9, 4, 1, 0),
        "linux_privilege_storyline": (
            "Privilege Escalation" in str(linux.incidents_df.iloc[0]["stage_progression"])
        ),
        "multi_source_regression": (
            multi.event_count,
            multi.alert_count,
            multi.incident_count,
            multi.quarantined_count,
        )
        == (22, 8, 2, 0),
        "semantic_deduplication": (
            multi_correlation.metrics.get("representative_alerts") == 7
            and multi_correlation.metrics.get("deduplicated_alerts") == 1
        ),
        "multi_source_incidents": (multi_correlation.metrics.get("multi_source_incidents") == 2),
        "multi_stage_incidents": (multi_correlation.metrics.get("multi_stage_incidents") == 2),
        "entity_resolution": multi_correlation.metrics.get("entities", 0) >= 8,
        "relationship_scoring": (
            multi_correlation.metrics.get("relationships", 0) >= 10
            and multi_correlation.metrics.get("cluster_relationships", 0) >= 5
        ),
        "graph_layers": {
            "incident",
            "alert",
            "entity",
            "technique",
            "tactic",
        }.issubset(node_types),
        "graph_relationships": {
            "contains_alert",
            "observed_entity",
            "maps_to_technique",
            "belongs_to_tactic",
        }.issubset(edge_types),
        "graph_hash": len(multi_correlation.graph_sha256) == 64,
        "graph_schema": (
            multi_correlation.graph_payload().get("schema") == "threatlens-attack-graph-1.0"
        ),
    }
    return {
        "checks": checks,
        "passed": all(checks.values()),
        "correlation_version": multi_correlation.version,
        "linux": {
            "events": linux.event_count,
            "alerts": linux.alert_count,
            "incidents": linux.incident_count,
            "metrics": linux_correlation.metrics,
            "stage_progression": linux.incidents_df.iloc[0]["stage_progression"],
        },
        "multi_source": {
            "events": multi.event_count,
            "alerts": multi.alert_count,
            "incidents": multi.incident_count,
            "metrics": multi_correlation.metrics,
            "incident_storylines": multi.incidents_df[
                ["incident_name", "stage_progression", "graph_score"]
            ].to_dict(orient="records"),
            "graph_sha256": multi_correlation.graph_sha256,
            "node_types": sorted(node_types),
            "edge_types": sorted(edge_types),
        },
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
