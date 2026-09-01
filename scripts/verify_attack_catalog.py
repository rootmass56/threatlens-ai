from __future__ import annotations

import json

from attack.catalog import AttackCatalog
from attack.coverage import build_attack_coverage_report
from attack.navigator import build_navigator_layer
from attack.service import AttackCatalogService
from attack.sources import (
    ALL_ATTACK_SOURCES,
    ALL_DOMAIN_EXPECTED_COUNTS,
    ensure_attack_bundle,
)
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader


def verification_report() -> dict:
    service = AttackCatalogService()
    domain_reports: dict[str, dict] = {}
    domain_checks: dict[str, bool] = {}
    enterprise_catalog: AttackCatalog | None = None

    for source in ALL_ATTACK_SOURCES:
        bundle_path = ensure_attack_bundle(source, allow_network=False)
        catalog = AttackCatalog.from_path(bundle_path, source)
        summary = catalog.validate_expected_counts()
        persisted = service.active_status(source.domain)
        domain_reports[source.domain] = {
            "display_name": source.display_name,
            "version": source.version,
            "collection_id": source.collection_id,
            "source_url": source.source_url,
            "modified": source.modified,
            "bundle_path": str(bundle_path),
            "content_sha256": catalog.content_sha256,
            "object_count": summary.object_count,
            "active_object_count": summary.active_object_count,
            "relationship_count": summary.relationship_count,
            "tactics": summary.tactic_count,
            "techniques": summary.technique_count,
            "subtechniques": summary.subtechnique_count,
            "catalog_awareness_percent": 100.0,
            "object_types": summary.object_types,
            "database": persisted,
        }
        domain_checks.update(
            {
                f"{source.domain}_version": source.version == "19.1",
                f"{source.domain}_tactics": summary.tactic_count == source.expected_tactics,
                f"{source.domain}_techniques": (
                    summary.technique_count == source.expected_techniques
                ),
                f"{source.domain}_subtechniques": (
                    summary.subtechnique_count == source.expected_subtechniques
                ),
                f"{source.domain}_database_present": persisted is not None,
                f"{source.domain}_database_counts": bool(
                    persisted
                    and persisted.get("object_count") == summary.object_count
                    and persisted.get("relationship_count") == summary.relationship_count
                    and persisted.get("tactic_count") == source.expected_tactics
                    and persisted.get("technique_count") == source.expected_techniques
                    and persisted.get("subtechnique_count") == source.expected_subtechniques
                ),
                f"{source.domain}_database_hash": bool(
                    persisted and persisted.get("content_sha256") == catalog.content_sha256
                ),
            }
        )
        if source.domain == "enterprise-attack":
            enterprise_catalog = catalog

    if enterprise_catalog is None:
        raise RuntimeError("Enterprise ATT&CK catalog was not loaded.")

    rules = RuleLoader(DEFAULT_RULE_DIRECTORY).load(enabled_only=False)
    coverage = build_attack_coverage_report(enterprise_catalog, rules)
    layer = build_navigator_layer(enterprise_catalog, coverage)
    enterprise_persisted = service.active_status("enterprise-attack")

    totals = {
        "domains": len(ALL_ATTACK_SOURCES),
        "tactics": sum(item["tactics"] for item in domain_reports.values()),
        "techniques": sum(item["techniques"] for item in domain_reports.values()),
        "subtechniques": sum(item["subtechniques"] for item in domain_reports.values()),
        "technique_records": sum(
            item["techniques"] + item["subtechniques"] for item in domain_reports.values()
        ),
        "catalog_awareness_percent": 100.0,
    }
    total_checks = {
        f"all_domain_{name}": totals[name] == expected
        for name, expected in ALL_DOMAIN_EXPECTED_COUNTS.items()
    }

    mapping_checks = {
        "all_enterprise_rule_mapping_ids_valid": coverage.invalid_mapping_count == 0,
        "all_mapping_justifications_present": all(
            bool(item.justification.strip()) for item in coverage.mappings
        ),
        "all_rule_tactics_reviewed": all(item.tactic_consistent for item in coverage.mappings),
        "navigator_domain": layer.get("domain") == "enterprise-attack",
        "navigator_version_pinned": layer.get("versions", {}).get("attack") == "19.1",
        "navigator_contains_all_mapped_ids": (
            len(layer.get("techniques", [])) == coverage.unique_mapped_attack_ids
        ),
        "database_mapping_count_matches": bool(
            enterprise_persisted
            and enterprise_persisted.get("mapping_count") == coverage.mapping_count
        ),
    }
    checks = {**domain_checks, **total_checks, **mapping_checks}

    return {
        "checks": checks,
        "passed": all(checks.values()),
        "pinned_release": "19.1",
        "all_domains": domain_reports,
        "all_domain_totals": totals,
        "enterprise_rule_coverage": coverage.summary(),
        "navigator": {
            "mapped_techniques": len(layer.get("techniques", [])),
            "domain": layer.get("domain"),
            "versions": layer.get("versions"),
        },
    }


def main() -> int:
    report = verification_report()
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
