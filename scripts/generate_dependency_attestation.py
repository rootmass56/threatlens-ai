from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import deque
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.release_inventory import ROOT_DIR

BASELINE = ROOT_DIR / "config" / "dependency_security_baseline.json"
DEFAULT_OUTPUT = ROOT_DIR / "data" / "dependency_attestation"
ACTIVE_EXTRAS = {"uvicorn": {"standard"}}


def _baseline_roots() -> list[str]:
    payload = json.loads(BASELINE.read_text(encoding="utf-8"))
    names: list[str] = []
    for section in ("build", "runtime", "development"):
        names.extend(payload[section])
    return names


def _dist(name: str):
    return metadata.distribution(name)


def _record_hash(dist) -> str | None:
    record = next(
        (path for path in (dist.files or []) if str(path).endswith(".dist-info/RECORD")),
        None,
    )
    if record is None:
        return None
    located = dist.locate_file(record)
    if not located.is_file():
        return None
    return hashlib.sha256(located.read_bytes()).hexdigest()


def _requirements_for(name: str) -> list[Requirement]:
    dist = _dist(name)
    output: list[Requirement] = []
    env = default_environment()
    extras = ACTIVE_EXTRAS.get(canonicalize_name(name), set())
    for raw in dist.requires or []:
        requirement = Requirement(raw)
        if requirement.marker is None:
            output.append(requirement)
            continue
        if requirement.marker.evaluate({**env, "extra": ""}):
            output.append(requirement)
            continue
        if any(requirement.marker.evaluate({**env, "extra": extra}) for extra in extras):
            output.append(requirement)
    return output


def _closure() -> tuple[dict[str, dict], dict[str, set[str]]]:
    queue = deque(_baseline_roots())
    components: dict[str, dict] = {}
    edges: dict[str, set[str]] = {}
    while queue:
        requested = queue.popleft()
        canonical = canonicalize_name(requested)
        if canonical in components:
            continue
        dist = _dist(requested)
        display_name = dist.metadata.get("Name") or requested
        installed_version = dist.version
        requires = _requirements_for(display_name)
        dependencies = {canonicalize_name(item.name) for item in requires}
        license_value = (
            dist.metadata.get("License-Expression") or dist.metadata.get("License") or "NOASSERTION"
        )
        components[canonical] = {
            "name": display_name,
            "version": installed_version,
            "license": str(license_value).strip() or "NOASSERTION",
            "record_sha256": _record_hash(dist),
        }
        edges[canonical] = dependencies
        for requirement in requires:
            queue.append(requirement.name)
    return components, edges


def _lock_text(components: dict[str, dict]) -> str:
    lines = [
        "# ThreatLens AI v0.12.0 resolved dependency lock",
        f"# Generated with CPython {platform.python_version()} on {platform.platform()}",
        "# record-sha256 values attest installed distribution metadata; they are not wheel hashes.",
        "",
    ]
    for canonical in sorted(components):
        item = components[canonical]
        suffix = f"  # record-sha256={item['record_sha256']}" if item["record_sha256"] else ""
        lines.append(f"{item['name']}=={item['version']}{suffix}")
    return "\n".join(lines) + "\n"


def _sbom(components: dict[str, dict], edges: dict[str, set[str]]) -> dict:
    serial_seed = "\n".join(f"{name}=={components[name]['version']}" for name in sorted(components))
    serial = hashlib.sha256(serial_seed.encode("utf-8")).hexdigest()
    items = []
    for canonical in sorted(components):
        item = components[canonical]
        component = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{canonical}@{item['version']}",
            "name": item["name"],
            "version": item["version"],
            "purl": f"pkg:pypi/{canonical}@{item['version']}",
            "licenses": [{"license": {"name": item["license"]}}],
        }
        if item["record_sha256"]:
            component["hashes"] = [{"alg": "SHA-256", "content": item["record_sha256"]}]
            component["properties"] = [
                {
                    "name": "threatlens:hash-scope",
                    "value": "installed-dist-info-record",
                }
            ]
        items.append(component)
    dependency_rows = [
        {
            "ref": f"pkg:pypi/{name}@{components[name]['version']}",
            "dependsOn": [
                f"pkg:pypi/{dep}@{components[dep]['version']}"
                for dep in sorted(edges.get(name, set()))
                if dep in components
            ],
        }
        for name in sorted(components)
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}"
        ),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "threatlens-ai",
                "version": "0.12.0",
            },
            "properties": [
                {"name": "threatlens:python", "value": platform.python_version()},
                {"name": "threatlens:platform", "value": platform.platform()},
            ],
        },
        "components": items,
        "dependencies": dependency_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture the exact installed transitive dependency closure and CycloneDX SBOM."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 11):
        raise SystemExit(
            "Dependency attestation must be generated in the supported CPython 3.11 environment."
        )
    components, edges = _closure()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    lock = args.output_dir / "requirements-lock-windows-py311.txt"
    sbom = args.output_dir / "cyclonedx-runtime-windows-py311.json"
    lock.write_text(_lock_text(components), encoding="utf-8")
    sbom.write_text(
        json.dumps(_sbom(components, edges), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(lock.read_bytes() + sbom.read_bytes()).hexdigest()
    report = {
        "release": "0.12.0",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "resolved_components": len(components),
        "lock_path": lock.as_posix(),
        "sbom_path": sbom.as_posix(),
        "combined_sha256": digest,
    }
    (args.output_dir / "dependency-attestation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
