class RuleError(RuntimeError):
    """Base exception for ThreatLens rule operations."""


class RuleLoadError(RuleError):
    """Raised when a YAML file cannot be loaded or validated."""


class DuplicateRuleError(RuleError):
    """Raised when duplicate rule IDs or detection names are discovered."""


class RuleEvaluationError(RuleError):
    """Raised when a validated rule cannot be evaluated safely."""
