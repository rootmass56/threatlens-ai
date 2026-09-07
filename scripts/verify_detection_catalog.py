from __future__ import annotations

import json
import sys

from core.rules import RuleFixtureRunner, RuleLoader, RuleQualityAnalyzer

EXPECTED_RULES = 46
EXPECTED_FIXTURES = 138
EXPECTED_DATASETS = {
    "linux_auth": 4,
    "suricata_eve": 8,
    "windows_security": 11,
    "windows_sysmon": 12,
    "zeek": 7,
}


def main() -> int:
    validation = RuleLoader().validation_report()
    fixtures = RuleFixtureRunner().run()
    quality = RuleQualityAnalyzer().summary()

    checks = {
        "catalog_valid": validation.valid,
        "rule_count": len(validation.rules) == EXPECTED_RULES,
        "fixtures_passed": fixtures.passed,
        "fixture_count": fixtures.passed_count == EXPECTED_FIXTURES,
        "lifecycle_complete": quality.lifecycle_completeness_percent == 100.0,
        "fixture_complete": quality.fixture_completeness_percent == 100.0,
        "review_current": quality.overdue_reviews == 0,
        "dataset_distribution": quality.rules_by_dataset == EXPECTED_DATASETS,
        "governance_score": quality.governance_score_percent >= 95.0,
    }
    payload = {
        "checks": checks,
        "validation": validation.summary(),
        "fixtures": {
            "passed": fixtures.passed,
            "passed_count": fixtures.passed_count,
            "failed_count": fixtures.failed_count,
            "duration_ms": fixtures.total_duration_ms,
        },
        "quality": quality.__dict__,
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
