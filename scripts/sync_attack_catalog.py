from __future__ import annotations

import argparse
import json

from attack.service import AttackCatalogService
from attack.sources import ATTACK_SOURCE_BY_DOMAIN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Download, validate, and transactionally persist complete pinned "
            "MITRE ATT&CK v19.1 catalogs."
        )
    )
    parser.add_argument(
        "--domain",
        choices=["all", *ATTACK_SOURCE_BY_DOMAIN],
        default="all",
        help="ATT&CK domain to synchronize. The default synchronizes Enterprise, Mobile and ICS.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use local pinned STIX bundles and never access the network.",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Redownload the pinned release even when a local bundle exists.",
    )
    parser.add_argument(
        "--actor",
        default="setup",
        help="Actor stored in the ThreatLens audit trail.",
    )
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    service = AttackCatalogService()
    if arguments.domain == "all":
        results = service.synchronize_all(
            allow_network=not arguments.offline,
            force_download=arguments.force_download,
            actor=arguments.actor,
        )
    else:
        result = service.synchronize(
            source=ATTACK_SOURCE_BY_DOMAIN[arguments.domain],
            allow_network=not arguments.offline,
            force_download=arguments.force_download,
            actor=arguments.actor,
            rules=(None if arguments.domain == "enterprise-attack" else ()),
        )
        results = (result,)
    print(json.dumps([item.as_dict() for item in results], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
