from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from attack.catalog import AttackCatalog
from attack.mapping import RuleAttackMappingRecord, build_rule_attack_mappings
from core.rules.models import ThreatLensRule


@dataclass(frozen=True, slots=True)
class AttackCoverageReport:
    catalog_version: str
    catalog_sha256: str
    catalog_tactics: int
    catalog_techniques: int
    catalog_subtechniques: int
    catalog_awareness_percent: float
    rule_count: int
    mapping_count: int
    valid_mapping_count: int
    invalid_mapping_count: int
    unique_mapped_attack_ids: int
    unique_mapped_techniques: int
    unique_mapped_subtechniques: int
    rule_coverage_percent: float
    tactic_rule_coverage: dict[str, int]
    dataset_mapping_coverage: dict[str, int]
    mapped_attack_ids: tuple[str, ...]
    unmapped_attack_ids: tuple[str, ...]
    mappings: tuple[RuleAttackMappingRecord, ...]

    def summary(self) -> dict[str, Any]:
        return {
            "catalog_version": self.catalog_version,
            "catalog_sha256": self.catalog_sha256,
            "catalog_tactics": self.catalog_tactics,
            "catalog_techniques": self.catalog_techniques,
            "catalog_subtechniques": self.catalog_subtechniques,
            "catalog_awareness_percent": self.catalog_awareness_percent,
            "rule_count": self.rule_count,
            "mapping_count": self.mapping_count,
            "valid_mapping_count": self.valid_mapping_count,
            "invalid_mapping_count": self.invalid_mapping_count,
            "unique_mapped_attack_ids": self.unique_mapped_attack_ids,
            "unique_mapped_techniques": self.unique_mapped_techniques,
            "unique_mapped_subtechniques": self.unique_mapped_subtechniques,
            "rule_coverage_percent": self.rule_coverage_percent,
            "tactic_rule_coverage": self.tactic_rule_coverage,
            "dataset_mapping_coverage": self.dataset_mapping_coverage,
        }

    def mapping_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": item.rule_id,
                "detection_name": item.detection_name,
                "rule_version": item.rule_version,
                "rule_status": item.rule_status,
                "dataset": item.dataset,
                "attack_id": item.attack_id,
                "catalog_name": item.catalog_name,
                "role": item.role,
                "confidence": item.confidence,
                "justification": item.justification,
                "declared_tactic": item.declared_tactic,
                "catalog_tactics": ", ".join(item.catalog_tactics),
                "valid_catalog_id": item.valid_catalog_id,
                "active_catalog_object": item.active_catalog_object,
                "tactic_consistent": item.tactic_consistent,
                "valid": item.valid,
            }
            for item in self.mappings
        ]


def build_attack_coverage_report(
    catalog: AttackCatalog,
    rules: Iterable[ThreatLensRule],
) -> AttackCoverageReport:
    rules = tuple(rules)
    mappings = build_rule_attack_mappings(catalog, rules)
    active_patterns = catalog.active_attack_patterns()
    all_attack_ids = {item.attack_id for item in active_patterns if item.attack_id is not None}
    valid_mapped_ids = {item.attack_id for item in mappings if item.valid}
    mapped_objects = [catalog.get_by_attack_id(attack_id) for attack_id in sorted(valid_mapped_ids)]
    mapped_techniques = sum(bool(item and not item.is_subtechnique) for item in mapped_objects)
    mapped_subtechniques = sum(bool(item and item.is_subtechnique) for item in mapped_objects)
    denominator = len(all_attack_ids)
    rule_coverage_percent = (
        round((len(valid_mapped_ids) / denominator) * 100, 2) if denominator else 0.0
    )

    tactic_counts: Counter[str] = Counter()
    dataset_ids: dict[str, set[str]] = defaultdict(set)
    for mapping in mappings:
        if not mapping.valid:
            continue
        for tactic in mapping.catalog_tactics or (mapping.declared_tactic,):
            tactic_counts[tactic] += 1
        dataset_ids[mapping.dataset or "unspecified"].add(mapping.attack_id)

    summary = catalog.summary()
    return AttackCoverageReport(
        catalog_version=catalog.source.version,
        catalog_sha256=catalog.content_sha256,
        catalog_tactics=summary.tactic_count,
        catalog_techniques=summary.technique_count,
        catalog_subtechniques=summary.subtechnique_count,
        catalog_awareness_percent=100.0,
        rule_count=len(rules),
        mapping_count=len(mappings),
        valid_mapping_count=sum(item.valid for item in mappings),
        invalid_mapping_count=sum(not item.valid for item in mappings),
        unique_mapped_attack_ids=len(valid_mapped_ids),
        unique_mapped_techniques=mapped_techniques,
        unique_mapped_subtechniques=mapped_subtechniques,
        rule_coverage_percent=rule_coverage_percent,
        tactic_rule_coverage=dict(sorted(tactic_counts.items())),
        dataset_mapping_coverage={
            dataset: len(attack_ids) for dataset, attack_ids in sorted(dataset_ids.items())
        },
        mapped_attack_ids=tuple(sorted(valid_mapped_ids)),
        unmapped_attack_ids=tuple(sorted(all_attack_ids - valid_mapped_ids)),
        mappings=mappings,
    )
