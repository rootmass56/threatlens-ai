from __future__ import annotations

import json
import sys

from core.rules import RuleFixtureRunner, RuleLoader, RuleQualityAnalyzer


def main() -> int:
    validation = RuleLoader().validation_report()
    fixtures = RuleFixtureRunner().run()
    quality = RuleQualityAnalyzer().summary()
    payload = {
        "validation": validation.summary(),
        "issues": [issue.__dict__ for issue in validation.issues],
        "fixtures": {
            "passed": fixtures.passed,
            "passed_count": fixtures.passed_count,
            "failed_count": fixtures.failed_count,
            "duration_ms": fixtures.total_duration_ms,
            "results": fixtures.records(),
        },
        "quality": quality.__dict__,
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0 if validation.valid and fixtures.passed else 1


if __name__ == "__main__":
    sys.exit(main())
