"""Backward-compatible facade for the advanced v0.8 correlation engine."""

from correlation.engine import INCIDENT_COLUMNS, advanced_correlate_alerts, correlate_alerts
from correlation.models import AdvancedCorrelationResult, CorrelationPolicy

__all__ = [
    "INCIDENT_COLUMNS",
    "AdvancedCorrelationResult",
    "CorrelationPolicy",
    "advanced_correlate_alerts",
    "correlate_alerts",
]
