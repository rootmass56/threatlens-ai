from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

from api.version import THREATLENS_VERSION
from scripts.openapi_contract import canonicalize_openapi

PACKAGE_NAMES = (
    "api",
    "app",
    "attack",
    "correlation",
    "core",
    "database",
    "rag",
    "rules",
)

EXPECTED_PATH_COUNT = 44
EXPECTED_OPERATION_COUNT = 45
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
ROOT_DIR = Path(__file__).resolve().parents[1]
OPENAPI_SNAPSHOT = ROOT_DIR / "docs" / "openapi_v0.12.0.json"


def main() -> None:
    os.environ.setdefault(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    for package_name in PACKAGE_NAMES:
        importlib.import_module(package_name)

    from api.main import app as api_app

    schema = canonicalize_openapi(api_app.openapi())
    paths = schema.get("paths", {})
    operation_count = sum(
        1 for path_item in paths.values() for method in path_item if method.lower() in HTTP_METHODS
    )
    path_count = len(paths)

    assert schema.get("info", {}).get("version") == THREATLENS_VERSION
    assert path_count == EXPECTED_PATH_COUNT, (
        f"Expected {EXPECTED_PATH_COUNT} OpenAPI paths, found {path_count}."
    )
    assert operation_count == EXPECTED_OPERATION_COUNT, (
        f"Expected {EXPECTED_OPERATION_COUNT} OpenAPI operations, found {operation_count}."
    )
    if not OPENAPI_SNAPSHOT.is_file():
        raise SystemExit(
            "Missing docs/openapi_v0.12.0.json. Run python -m scripts.generate_openapi_snapshot."
        )
    expected_schema = json.loads(OPENAPI_SNAPSHOT.read_text(encoding="utf-8"))
    assert schema == expected_schema, (
        "Generated canonical OpenAPI differs from docs/openapi_v0.12.0.json; "
        "regenerate and review the snapshot."
    )

    print(
        "ThreatLens AI imports and OpenAPI contract passed: "
        f"{path_count} paths / {operation_count} operations; canonical snapshot exact."
    )


if __name__ == "__main__":
    main()
