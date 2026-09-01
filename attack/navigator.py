from __future__ import annotations

from typing import Any

from attack.catalog import AttackCatalog
from attack.coverage import AttackCoverageReport

NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"


def _score_for_mapping_count(mapping_count: int) -> int:
    return min(100, 20 + max(mapping_count - 1, 0) * 15)


def build_navigator_layer(
    catalog: AttackCatalog,
    coverage: AttackCoverageReport,
    *,
    name: str = "ThreatLens AI Validated Detection Coverage",
    description: str | None = None,
) -> dict[str, Any]:
    """Build an ATT&CK Navigator-compatible Enterprise layer."""

    counts: dict[str, int] = {}
    comments: dict[str, list[str]] = {}
    for mapping in coverage.mappings:
        if not mapping.valid:
            continue
        counts[mapping.attack_id] = counts.get(mapping.attack_id, 0) + 1
        comments.setdefault(mapping.attack_id, []).append(
            f"{mapping.detection_name} v{mapping.rule_version} ({mapping.dataset or 'unspecified'})"
        )

    techniques = []
    for attack_id in sorted(counts):
        record = catalog.get_by_attack_id(attack_id)
        techniques.append(
            {
                "techniqueID": attack_id,
                "score": _score_for_mapping_count(counts[attack_id]),
                "color": "#2E7D32",
                "comment": "; ".join(sorted(comments[attack_id])),
                "enabled": True,
                "metadata": [
                    {"name": "ATT&CK name", "value": record.name if record else "Unknown"},
                    {"name": "Validated rule mappings", "value": str(counts[attack_id])},
                    {"name": "Catalog version", "value": catalog.source.version},
                ],
                "links": (
                    [{"label": "MITRE ATT&CK", "url": record.external_url}]
                    if record and record.external_url
                    else []
                ),
                "showSubtechniques": True,
            }
        )

    return {
        "name": name,
        "versions": {
            "attack": catalog.source.version,
            "navigator": NAVIGATOR_VERSION,
            "layer": NAVIGATOR_LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description
        or (
            "Validated ThreatLens AI rule mappings. Catalog awareness is complete for the "
            "pinned Enterprise ATT&CK release; highlighted cells represent only evidence-backed "
            "detection-rule coverage."
        ),
        "filters": {"platforms": []},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#FFF5F5", "#FFB74D", "#2E7D32"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Validated detection mapping", "color": "#2E7D32"},
        ],
        "metadata": [
            {"name": "Catalog awareness", "value": "100%"},
            {
                "name": "Catalog techniques and sub-techniques",
                "value": str(coverage.catalog_techniques + coverage.catalog_subtechniques),
            },
            {"name": "Mapped ATT&CK IDs", "value": str(coverage.unique_mapped_attack_ids)},
            {"name": "Rule coverage percentage", "value": f"{coverage.rule_coverage_percent:.2f}%"},
            {"name": "Catalog SHA-256", "value": coverage.catalog_sha256},
        ],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#EEEEEE",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
