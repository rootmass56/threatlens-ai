"""External-rule detection entry points."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.rules.engine import ALERT_COLUMNS, RuleEngine
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.models import ThreatLensRule


def detect_alerts(
    events_df: pd.DataFrame,
    *,
    rules: list[ThreatLensRule] | None = None,
    rule_directory: Path = DEFAULT_RULE_DIRECTORY,
) -> pd.DataFrame:
    """Evaluate schema-normalized events with validated external YAML rules."""

    loaded_rules = rules if rules is not None else RuleLoader(rule_directory).load()
    return RuleEngine(loaded_rules).evaluate(events_df)


__all__ = ["ALERT_COLUMNS", "detect_alerts"]
