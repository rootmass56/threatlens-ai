
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from attack.catalog import AttackCatalog
from attack.coverage import build_attack_coverage_report
from attack.mapping import tactic_is_consistent
from attack.navigator import build_navigator_layer
from attack.sources import AttackCatalogSource

FIXTURE = Path("tests/fixtures/attack/enterprise-mini.json")
SOURCE = AttackCatalogSource(
    domain="enterprise-test",
    display_name="Enterprise ATT&CK Test",
    version="test",
    collection_id="x-mitre-collection--test",
    source_url="https://raw.githubusercontent.com/example/test.json",
    modified="2026-01-01T00:00:00.000Z",
    expected_tactics=2,
    expected_techniques=2,
    expected_subtechniques=2,
)


def _mapping(attack_id: str, tactic: str):
    return SimpleNamespace(
        technique_id=attack_id,
        tactic=tactic,
        role="primary",
        confidence=0.9,
        justification="Synthetic evidence-backed mapping for tests.",
    )


def _rule(attack_id: str, tactic: str, name: str = "synthetic_rule"):
    return SimpleNamespace(
        rule_id="11111111-1111-4111-8111-111111111111",
        detection_name=name,
        version=1,
        status=SimpleNamespace(value="stable"),
        logsource=SimpleNamespace(dataset="synthetic"),
        attack=[_mapping(attack_id, tactic)],
    )


def test_complete_catalog_parsing_and_subtechnique_parentage() -> None:
    catalog = AttackCatalog.from_path(FIXTURE, SOURCE)
    summary = catalog.validate_expected_counts()
    assert summary.tactic_count == 2
    assert summary.technique_count == 2
    assert summary.subtechnique_count == 2
    assert summary.relationship_count == 3
    assert catalog.get_by_attack_id("T1000.001").parent_attack_id == "T1000"
    assert catalog.get_by_attack_id("T3000").active is False
    assert catalog.tactic_order == ("initial-access", "execution")


def test_coverage_separates_catalog_awareness_from_rule_coverage() -> None:
    catalog = AttackCatalog.from_path(FIXTURE, SOURCE)
    coverage = build_attack_coverage_report(
        catalog,
        [_rule("T1000.001", "Initial Access")],
    )
    assert coverage.catalog_awareness_percent == 100.0
    assert coverage.unique_mapped_attack_ids == 1
    assert coverage.rule_coverage_percent == 25.0
    assert coverage.invalid_mapping_count == 0
    assert len(coverage.unmapped_attack_ids) == 3


def test_invalid_rule_mapping_is_reported_not_silently_accepted() -> None:
    catalog = AttackCatalog.from_path(FIXTURE, SOURCE)
    coverage = build_attack_coverage_report(
        catalog,
        [_rule("T9999", "Execution")],
    )
    assert coverage.valid_mapping_count == 0
    assert coverage.invalid_mapping_count == 1


def test_navigator_layer_contains_only_validated_mapped_ids() -> None:
    catalog = AttackCatalog.from_path(FIXTURE, SOURCE)
    coverage = build_attack_coverage_report(
        catalog,
        [
            _rule("T1000.001", "Initial Access", "first_rule"),
            _rule("T2000", "Execution", "second_rule"),
        ],
    )
    layer = build_navigator_layer(catalog, coverage)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "test"
    assert layer["versions"]["navigator"] == "5.3.2"
    assert {item["techniqueID"] for item in layer["techniques"]} == {
        "T1000.001",
        "T2000",
    }
    assert "Catalog awareness is complete" in layer["description"]


def test_v19_legacy_defense_evasion_alias_is_reviewed_consistently() -> None:
    assert tactic_is_consistent("Defense Evasion", ("Stealth",))
    assert tactic_is_consistent("Defense Evasion", ("Defense Impairment",))
    assert not tactic_is_consistent("Execution", ("Persistence",))
