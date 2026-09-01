from __future__ import annotations

from typing import Final

VALID_INCIDENT_STATUSES: Final[frozenset[str]] = frozenset(
    {"open", "investigating", "contained", "resolved", "false_positive"}
)
VALID_PRIORITIES: Final[frozenset[str]] = frozenset({"P1", "P2", "P3", "P4"})
CLOSING_STATUSES: Final[frozenset[str]] = frozenset({"resolved", "false_positive"})
ALLOWED_STATUS_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "open": frozenset({"open", "investigating", "false_positive"}),
    "investigating": frozenset({"investigating", "contained", "resolved", "false_positive"}),
    "contained": frozenset({"contained", "investigating", "resolved"}),
    "resolved": frozenset({"resolved", "investigating"}),
    "false_positive": frozenset({"false_positive", "investigating"}),
}
