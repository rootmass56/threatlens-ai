from pathlib import Path


def test_batch6h_path_dropdowns_use_relationship_endpoints() -> None:
    source = Path(
        "frontend/src/pages/AdvancedSocPages.tsx"
    ).read_text(encoding="utf-8")

    required = (
        "const pathEndpointKeys=Array.from(new Set(",
        "edges.flatMap",
        "value(row,['source','source_node_key'],'')",
        "value(row,['target','target_node_key'],'')",
        "pathEndpointOptions.map",
        "disabled={edges.length===0 || !pathSource || !pathTarget}",
        "The selected incident has no persisted relationships",
        "Path traversal uses the persisted relationship endpoint keys",
    )

    for marker in required:
        assert marker in source


def test_batch6h_path_dropdowns_do_not_use_entity_node_options() -> None:
    source = Path(
        "frontend/src/pages/AdvancedSocPages.tsx"
    ).read_text(encoding="utf-8")

    assert "key={`source-${option.key}`} value={option.key}>{option.type} | {option.label}" not in source
    assert "key={`target-${option.key}`} value={option.key}>{option.type} | {option.label}" not in source