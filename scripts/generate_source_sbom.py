from __future__ import annotations

import hashlib
import json

from api.version import THREATLENS_VERSION
from scripts.release_inventory import ROOT_DIR

BASELINE = ROOT_DIR / "config" / "dependency_security_baseline.json"
OUTPUT = ROOT_DIR / "sbom" / f"source-dependencies-v{THREATLENS_VERSION}.cdx.json"


def main() -> None:
    payload = json.loads(BASELINE.read_text(encoding="utf-8"))
    if payload.get("release") != THREATLENS_VERSION:
        raise SystemExit(
            f"Dependency baseline release {payload.get('release')!r} does not match "
            f"ThreatLens {THREATLENS_VERSION}."
        )
    components = []
    for scope in ("build", "runtime", "development"):
        for name, version in sorted(payload[scope].items(), key=lambda item: item[0].lower()):
            canonical = name.lower().replace("_", "-")
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"pkg:pypi/{canonical}@{version}",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{canonical}@{version}",
                    "scope": "required" if scope != "development" else "optional",
                    "properties": [
                        {"name": "threatlens:dependency-scope", "value": scope},
                        {
                            "name": "threatlens:resolution",
                            "value": (
                                "direct-reviewed-pin; transitive closure is attested "
                                "after installation"
                            ),
                        },
                    ],
                }
            )
    seed = "\n".join(f"{item['name']}=={item['version']}" for item in components)
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        ),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "threatlens-ai",
                "version": THREATLENS_VERSION,
            },
            "properties": [
                {
                    "name": "threatlens:sbom-scope",
                    "value": (
                        "source direct dependencies; use scripts.generate_dependency_attestation "
                        "for installed transitive closure"
                    ),
                }
            ],
        },
        "components": components,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Generated {OUTPUT.relative_to(ROOT_DIR)} with {len(components)} reviewed components.")


if __name__ == "__main__":
    main()
