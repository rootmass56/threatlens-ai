from __future__ import annotations

from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader


def _rule(detection_name: str):
    rules = RuleLoader(DEFAULT_RULE_DIRECTORY).load(enabled_only=False)
    return next(rule for rule in rules if rule.detection_name == detection_name)


def test_deprecated_attack_ids_are_migrated_to_active_v19_1_ids() -> None:
    image_load = _rule("sysmon_image_load_user_writable")
    audit_cleared = _rule("windows_audit_log_cleared")
    audit_policy = _rule("windows_audit_policy_changed")

    assert image_load.version == 2
    assert image_load.attack[0].technique_id == "T1574.001"
    assert image_load.attack[0].tactic == "Stealth"

    assert audit_cleared.version == 2
    assert audit_cleared.attack[0].technique_id == "T1685.005"
    assert audit_cleared.attack[0].tactic == "Defense Impairment"

    assert audit_policy.version == 2
    assert audit_policy.attack[0].technique_id == "T1685.001"
    assert audit_policy.attack[0].tactic == "Defense Impairment"


def test_no_retired_attack_ids_remain_in_governed_rules() -> None:
    rules = RuleLoader(DEFAULT_RULE_DIRECTORY).load(enabled_only=False)
    attack_ids = {mapping.technique_id for rule in rules for mapping in rule.attack}

    assert "T1574.002" not in attack_ids
    assert "T1070.001" not in attack_ids
    assert "T1562.002" not in attack_ids
