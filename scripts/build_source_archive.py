from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from api.version import THREATLENS_VERSION
from scripts.release_inventory import CURRENT_MANIFEST, ROOT_DIR, release_paths
from scripts.verify_source_archive import verify_archive


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_archive(output: Path, report: Path | None = None) -> dict[str, object]:
    manifest_path = ROOT_DIR / CURRENT_MANIFEST
    if not manifest_path.is_file():
        raise RuntimeError(
            f"{CURRENT_MANIFEST} is missing. Run python -m scripts.generate_release_manifest first."
        )

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    members = release_paths() + [manifest_path]
    seen: set[str] = set()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in sorted(members, key=lambda item: item.relative_to(ROOT_DIR).as_posix()):
            relative = source.relative_to(ROOT_DIR).as_posix()
            if relative in seen:
                raise RuntimeError(f"Duplicate archive member candidate: {relative}")
            seen.add(relative)
            info = zipfile.ZipInfo(relative)
            # Deterministic DOS timestamp so repeat packaging does not change
            # merely due to wall clock.
            info.date_time = (2026, 8, 26, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, source.read_bytes())

    verify_archive(output)
    with zipfile.ZipFile(output) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        corrupt = archive.testzip()
        manifest = json.loads(archive.read(CURRENT_MANIFEST).decode("utf-8"))

    payload: dict[str, object] = {
        "product": "ThreatLens AI",
        "release": THREATLENS_VERSION,
        "release_title": "Full React Feature-Parity Release Candidate",
        "generated_utc": datetime.now(UTC).isoformat(),
        "archive": str(output),
        "archive_sha256": _sha256(output),
        "archive_size_bytes": output.stat().st_size,
        "archive_members": len(names),
        "unique_members": len(set(names)),
        "zip_integrity": "passed" if corrupt is None else f"failed:{corrupt}",
        "manifest_records": len(manifest.get("files") or []),
        "manifest_version": manifest.get("version"),
        "governed_windows_test_target": 271,
        "platform_independent_test_target": 270,
        "feature_parity_policy": "15/15 legacy analyst surfaces migrated/superseded",
        "deployment_status": (
            "release candidate; deployment freeze requires Windows gate + UAT + "
            "staging/live deployment"
        ),
    }
    if report is not None:
        report = report.resolve()
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build and independently verify a clean ThreatLens source ZIP."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    payload = build_archive(args.output, args.report)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
