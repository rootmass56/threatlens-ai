from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from scripts.release_inventory import ROOT_DIR

DEFAULT_LOCK = ROOT_DIR / "data" / "dependency_attestation" / "requirements-lock-windows-py311.txt"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"


def _parse_lock(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        raise SystemExit(f"Dependency lock does not exist: {path}")
    packages: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "==" not in line:
            continue
        name, version = line.split("==", 1)
        packages.append((name.strip(), version.strip()))
    if not packages:
        raise SystemExit("Dependency lock contains no exact package pins.")
    return packages


def _request(packages: list[tuple[str, str]], timeout: int) -> dict:
    body = {
        "queries": [
            {"package": {"ecosystem": "PyPI", "name": name}, "version": version}
            for name, version in packages
        ]
    }
    request = urllib.request.Request(
        OSV_QUERY_BATCH,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "ThreatLens/0.12.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise SystemExit(
            f"OSV dependency audit could not complete: {type(error).__name__}"
        ) from error


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Query OSV for vulnerabilities in the exact installed ThreatLens dependency lock."
        )
    )
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    packages = _parse_lock(args.lock)
    payload = _request(packages, max(args.timeout, 1))
    results = payload.get("results") or []
    findings: list[dict[str, object]] = []
    for (name, version), result in zip(packages, results, strict=False):
        vulns = result.get("vulns") or []
        if vulns:
            findings.append(
                {
                    "package": name,
                    "version": version,
                    "vulnerability_ids": sorted(
                        {
                            str(vuln.get("id"))
                            for vuln in vulns
                            if re.match(r"^[A-Za-z0-9_.:-]+$", str(vuln.get("id") or ""))
                        }
                    ),
                }
            )
    if findings:
        print(json.dumps({"status": "blocked", "findings": findings}, indent=2, sort_keys=True))
        raise SystemExit("OSV reported vulnerabilities in the exact dependency lock.")
    print(
        json.dumps(
            {"status": "passed", "packages_checked": len(packages), "findings": []},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
