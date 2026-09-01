from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.connectors.base import SecurityLogConnector
from core.schema import ParserResult, SourceValidationResult


class ConnectorNotFoundError(LookupError):
    """Raised when no registered connector can safely handle a source."""


class DuplicateConnectorError(ValueError):
    """Raised when two connectors declare the same connector identifier."""


@dataclass(frozen=True)
class ConnectorDetection:
    connector: SecurityLogConnector
    validation: SourceValidationResult


class ConnectorRegistry:
    """Register, discover and invoke security-log connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, SecurityLogConnector] = {}

    def register(self, connector: SecurityLogConnector) -> None:
        connector_id = connector.metadata.connector_id
        if connector_id in self._connectors:
            raise DuplicateConnectorError(f"Connector already registered: {connector_id}")
        self._connectors[connector_id] = connector

    def get(self, connector_id: str) -> SecurityLogConnector:
        try:
            return self._connectors[connector_id]
        except KeyError as error:
            raise ConnectorNotFoundError(
                f"Unknown connector '{connector_id}'. Available: {', '.join(self.connector_ids())}"
            ) from error

    def connector_ids(self) -> list[str]:
        return sorted(self._connectors)

    def diagnostics(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
    ) -> list[ConnectorDetection]:
        """Return validation evidence from every registered connector."""

        return sorted(
            [
                ConnectorDetection(
                    connector=connector,
                    validation=connector.validate_source(raw_content, filename=filename),
                )
                for connector in self._connectors.values()
            ],
            key=lambda item: item.validation.confidence,
            reverse=True,
        )

    def metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "connector_id": connector.metadata.connector_id,
                "name": connector.metadata.name,
                "product": connector.metadata.product,
                "service": connector.metadata.service,
                "category": connector.metadata.category,
                "parser_version": connector.metadata.parser_version,
                "supported_extensions": ", ".join(connector.metadata.supported_extensions),
                "description": connector.metadata.description,
            }
            for connector in sorted(
                self._connectors.values(),
                key=lambda item: item.metadata.connector_id,
            )
        ]

    def detect(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
        minimum_confidence: float = 0.50,
    ) -> ConnectorDetection:
        candidates = self.diagnostics(raw_content, filename=filename)
        valid = [
            candidate
            for candidate in candidates
            if candidate.validation.valid and candidate.validation.confidence >= minimum_confidence
        ]
        if not valid:
            reasons = [
                f"{item.connector.metadata.connector_id}: "
                f"{'; '.join(item.validation.reasons) or 'not recognized'}"
                for item in candidates
            ]
            raise ConnectorNotFoundError(
                "No connector recognized the source. " + " | ".join(reasons)
            )
        return max(valid, key=lambda item: item.validation.confidence)

    def parse(
        self,
        raw_content: str | bytes,
        *,
        filename: str | None = None,
        connector_id: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> ParserResult:
        connector = (
            self.get(connector_id)
            if connector_id
            else self.detect(
                raw_content,
                filename=filename,
            ).connector
        )
        return connector.parse(raw_content, filename=filename, options=options)
