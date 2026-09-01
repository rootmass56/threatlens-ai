"""Advanced cross-source correlation and attack-graph capabilities."""

from correlation.engine import advanced_correlate_alerts, correlate_alerts
from correlation.models import (
    CORRELATION_VERSION,
    AdvancedCorrelationResult,
    CorrelationPolicy,
)

__all__ = [
    "CORRELATION_VERSION",
    "AdvancedCorrelationResult",
    "CorrelationPolicy",
    "advanced_correlate_alerts",
    "correlate_alerts",
]
