from __future__ import annotations

from copy import deepcopy
from typing import Any


def canonicalize_openapi(schema: dict[str, Any]) -> dict[str, Any]:
    """Normalize known OpenAPI dialect differences without weakening the contract.

    FastAPI/Pydantic releases may describe multipart binary string fields as either
    ``format: binary`` or ``contentMediaType: application/octet-stream``. ThreatLens
    pins its Windows runtime, but canonicalizing this equivalent representation keeps
    release snapshots reproducible across audit environments while preserving every
    route, security requirement, media type, property and validation constraint.
    """

    result = deepcopy(schema)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if (
                value.get("type") == "string"
                and value.get("contentMediaType") == "application/octet-stream"
            ):
                value.pop("contentMediaType", None)
                value["format"] = "binary"
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(result)
    return result
