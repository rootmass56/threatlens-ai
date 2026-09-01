from __future__ import annotations

import json
import os
from pathlib import Path

from api.version import THREATLENS_VERSION
from scripts.openapi_contract import canonicalize_openapi

ROOT_DIR = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT_DIR / "docs" / "openapi_v0.12.0.json"


def main() -> None:
    os.environ.setdefault(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api.main import app

    schema = canonicalize_openapi(app.openapi())
    if schema.get("info", {}).get("version") != THREATLENS_VERSION:
        raise SystemExit("OpenAPI version does not match the ThreatLens application version.")
    OUTPUT_PATH.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Generated {OUTPUT_PATH.relative_to(ROOT_DIR)} for ThreatLens {THREATLENS_VERSION}.")


if __name__ == "__main__":
    main()
