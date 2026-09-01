from __future__ import annotations

import json

from api.version import THREATLENS_VERSION
from scripts.release_inventory import CURRENT_MANIFEST, ROOT_DIR, file_record, release_paths

MANIFEST_PATH = ROOT_DIR / CURRENT_MANIFEST


def main() -> None:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"Missing release manifest: {CURRENT_MANIFEST}")
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if payload.get("version") != THREATLENS_VERSION:
        raise SystemExit(
            f"Manifest version {payload.get('version')!r} does not match {THREATLENS_VERSION!r}."
        )

    expected_records = [file_record(path) for path in release_paths()]
    actual_records = payload.get("files")
    if not isinstance(actual_records, list):
        raise SystemExit("Manifest files entry is not a list.")

    expected_by_path = {str(record["path"]): record for record in expected_records}
    actual_by_path = {str(record.get("path")): record for record in actual_records}
    missing = sorted(set(expected_by_path) - set(actual_by_path))
    extra = sorted(set(actual_by_path) - set(expected_by_path))
    mismatched = sorted(
        path
        for path in set(expected_by_path) & set(actual_by_path)
        if expected_by_path[path] != actual_by_path[path]
    )
    if missing or extra or mismatched:
        details = {
            "missing": missing,
            "extra": extra,
            "hash_or_size_mismatch": mismatched,
        }
        raise SystemExit("Release manifest verification failed:\n" + json.dumps(details, indent=2))

    print(
        f"Release manifest verified for ThreatLens {THREATLENS_VERSION}: "
        f"{len(expected_records)} releasable files, 0 mismatches."
    )


if __name__ == "__main__":
    main()
