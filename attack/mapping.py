from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from attack.catalog import AttackCatalog
from core.rules.models import ThreatLensRule


@dataclass(frozen=True, slots=True)
class RuleAttackMappingRecord:
    rule_id: str
    detection_name: str
    rule_version: int
    rule_status: str
    dataset: str | None
    attack_id: str
    catalog_stix_id: str | None
    catalog_name: str | None
    role: str
    confidence: float
    justification: str
    declared_tactic: str
    catalog_tactics: tuple[str, ...]
    valid_catalog_id: bool
    active_catalog_object: bool
    tactic_consistent: bool

    @property
    def valid(self) -> bool:
        return (
            self.valid_catalog_id
            and self.active_catalog_object
            and self.tactic_consistent
            and bool(self.justification.strip())
        )


def normalize_tactic(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def tactic_is_consistent(declared_tactic: str, catalog_tactics: tuple[str, ...]) -> bool:
    """Validate tactic labels while accepting ATT&CK v19 taxonomy migration aliases."""

    if not catalog_tactics:
        return True
    declared = normalize_tactic(declared_tactic)
    normalized_catalog = {normalize_tactic(item) for item in catalog_tactics}
    if declared in normalized_catalog:
        return True
    # ATT&CK v19 split the legacy Defense Evasion tactic into Stealth and
    # Defense Impairment. Existing governed rules remain reviewable during
    # migration without being incorrectly treated as invalid technique IDs.
    if declared == "defenseevasion":
        return bool(normalized_catalog & {"stealth", "defenseimpairment"})
    return False


def build_rule_attack_mappings(
    catalog: AttackCatalog,
    rules: Iterable[ThreatLensRule],
) -> tuple[RuleAttackMappingRecord, ...]:
    tactic_names = {
        item.shortname: item.name for item in catalog.tactic_records() if item.shortname is not None
    }
    records: list[RuleAttackMappingRecord] = []
    for rule in rules:
        for mapping in rule.attack:
            catalog_object = catalog.get_by_attack_id(mapping.technique_id)
            catalog_tactics = (
                tuple(
                    tactic_names.get(shortname, shortname)
                    for shortname in catalog_object.tactic_shortnames
                )
                if catalog_object
                else ()
            )
            tactic_consistent = tactic_is_consistent(
                mapping.tactic,
                catalog_tactics,
            )
            records.append(
                RuleAttackMappingRecord(
                    rule_id=rule.rule_id,
                    detection_name=rule.detection_name,
                    rule_version=rule.version,
                    rule_status=rule.status.value,
                    dataset=rule.logsource.dataset,
                    attack_id=mapping.technique_id,
                    catalog_stix_id=catalog_object.stix_id if catalog_object else None,
                    catalog_name=catalog_object.name if catalog_object else None,
                    role=mapping.role,
                    confidence=mapping.confidence,
                    justification=mapping.justification,
                    declared_tactic=mapping.tactic,
                    catalog_tactics=catalog_tactics,
                    valid_catalog_id=catalog_object is not None,
                    active_catalog_object=bool(catalog_object and catalog_object.active),
                    tactic_consistent=tactic_consistent,
                )
            )
    return tuple(records)
