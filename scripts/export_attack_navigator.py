from __future__ import annotations

import argparse
from pathlib import Path

from attack.service import AttackCatalogService


def main() -> int:
    parser = argparse.ArgumentParser(description="Export ThreatLens ATT&CK Navigator layer JSON.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("exports/attack/threatlens-enterprise-attack-v19.1-layer.json"),
    )
    arguments = parser.parse_args()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_bytes(AttackCatalogService().navigator_json())
    print(arguments.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
