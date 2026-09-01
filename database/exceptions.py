
class PersistenceError(RuntimeError):
    """Base exception for ThreatLens AI persistence operations."""


class DuplicateAnalysisError(PersistenceError):
    """Raised when the same input was already analyzed."""

    def __init__(self, existing_session_uuid: str) -> None:
        self.existing_session_uuid = existing_session_uuid

        super().__init__(
            "This log source was already analyzed. "
            f"Existing analysis session: {existing_session_uuid}"
        )


class IncidentNotFoundError(PersistenceError):
    """Raised when an incident UUID does not exist."""


class InvalidIncidentStateError(PersistenceError):
    """Raised when an unsupported incident state is requested."""
