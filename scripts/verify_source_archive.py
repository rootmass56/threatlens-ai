from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from api.version import THREATLENS_VERSION
from scripts.release_inventory import (
    CURRENT_MANIFEST,
    canonical_release_bytes_from_data,
    is_release_relative_path,
)


def _record(relative: str, data: bytes) -> dict[str, object]:
    canonical, content_mode = canonical_release_bytes_from_data(data)
    return {
        "path": relative,
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "size_bytes": len(canonical),
        "content_mode": content_mode,
    }


def verify_archive(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"Archive does not exist: {path}")
    with zipfile.ZipFile(path) as archive:
        corrupt = archive.testzip()
        if corrupt is not None:
            raise SystemExit(f"ZIP integrity test failed at: {corrupt}")
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        if len(names) != len(set(names)):
            raise SystemExit("ZIP contains duplicate member names.")
        unsafe = [
            name
            for name in names
            if name.startswith(("/", "\\")) or ".." in Path(name.replace("\\", "/")).parts
        ]
        if unsafe:
            raise SystemExit("ZIP contains unsafe member paths: " + ", ".join(unsafe))
        nested = sorted(name for name in names if name.lower().endswith(".zip"))
        if nested:
            raise SystemExit(
                "Release archive contains nested ZIP artifacts excluded from manifest policy: "
                + ", ".join(nested)
            )
        if CURRENT_MANIFEST not in names:
            raise SystemExit(f"Archive is missing {CURRENT_MANIFEST}.")

        manifest = json.loads(archive.read(CURRENT_MANIFEST).decode("utf-8"))
        if manifest.get("version") != THREATLENS_VERSION:
            raise SystemExit(
                f"Manifest version {manifest.get('version')!r} does not match "
                f"{THREATLENS_VERSION!r}."
            )
        expected = {
            name: _record(name, archive.read(name))
            for name in names
            if is_release_relative_path(name)
        }
        records = manifest.get("files")
        if not isinstance(records, list):
            raise SystemExit("Manifest files entry is not a list.")
        actual = {str(record.get("path")): record for record in records}
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        mismatched = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )
        if missing or extra or mismatched:
            raise SystemExit(
                "Source archive manifest verification failed:\n"
                + json.dumps(
                    {
                        "missing": missing,
                        "extra": extra,
                        "hash_or_size_mismatch": mismatched,
                    },
                    indent=2,
                )
            )
        print(
            f"Source archive verified for ThreatLens {THREATLENS_VERSION}: "
            f"{len(names)} files, {len(expected)} releasable records, 0 mismatches."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a ThreatLens Git-archive ZIP.")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    verify_archive(args.archive)


if __name__ == "__main__":
    main()
