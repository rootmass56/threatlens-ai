from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from core.schema import ParserResult, SourceValidationResult


@dataclass(frozen=True)
class ConnectorMetadata:
    """Stable metadata advertised by a security-log connector."""

    connector_id: str
    name: str
    product: str
    service: str
    category: str
    parser_version: str
    supported_extensions: tuple[str, ...]
    description: str


class SecurityLogConnector(ABC):
    """Interface implemented by every ThreatLens telemetry connector."""

    metadata: ConnectorMetadata

    @abstractmethod
    def validate_source(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
    ) -> SourceValidationResult:
        """Return whether this connector can safely parse the source."""

    @abstractmethod
    def parse(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Normalize the source into the common event schema."""
