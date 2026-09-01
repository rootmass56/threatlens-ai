from pathlib import Path


def test_batch6h_graph_intelligence_ui_exposes_complete_analyst_workflow() -> None:
    source = Path(
        "frontend/src/pages/AdvancedSocPages.tsx"
    ).read_text(encoding="utf-8")

    required = (
        'title="Graph filters"',
        'title="Interactive evidence path"',
        'title="Entity timeline"',
        'title="Global investigation search"',
        "/api/v1/incidents?limit=1000",
        "/graph/intelligence?minimum_confidence=",
        "&entity_type=",
        "/graph/path",
        "/timeline?limit=250",
        "/api/v1/search?q=",
        "Previous page",
        "Next page",
        "searchLimit=25",
        "threatlens-graph-nodes",
        "threatlens-graph-edges",
        "threatlens-graph-path",
        "threatlens-entity-timeline",
        "threatlens-global-search",
    )

    for marker in required:
        assert marker in source