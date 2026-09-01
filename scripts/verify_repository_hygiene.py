from __future__ import annotations

import fnmatch
import shutil
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]


def _forbidden_tracked(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = Path(normalized).name
    if normalized == ".env" or (normalized.startswith(".env.") and normalized != ".env.example"):
        return True
    if normalized == ".streamlit/secrets.toml":
        return True
    if normalized == "data/bootstrap_admin_credentials.txt":
        return True
    if name.lower().endswith(".zip"):
        return True
    if normalized.startswith("database/") and any(
        fnmatch.fnmatch(name, pattern)
        for pattern in ("*.db", "*.db-wal", "*.db-shm", "*.sqlite", "*.sqlite3")
    ):
        return True
    if normalized.startswith("data/attack/") and (
        fnmatch.fnmatch(name, "*-attack-*.json") or fnmatch.fnmatch(name, "*.metadata.json")
    ):
        return True
    if normalized.startswith("data/reports/") and name.lower().endswith(".pdf"):
        return True
    if normalized.startswith("data/rag/"):
        return True
    if normalized.startswith("data/dependency_attestation/"):
        return True
    if normalized.startswith("exports/openapi/") or normalized.startswith("exports/attack/"):
        return True
    return False


def main() -> None:
    git = shutil.which("git")
    if git is None or not (ROOT_DIR / ".git").exists():
        print("Repository hygiene: Git metadata unavailable; tracked-file check skipped.")
        return
    result = subprocess.run(
        [git, "ls-files", "-z"],
        cwd=ROOT_DIR,
        check=True,
        capture_output=True,
    )
    tracked = [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]
    forbidden = sorted(path for path in tracked if _forbidden_tracked(path))
    if forbidden:
        raise SystemExit(
            "Forbidden runtime/security/release material is tracked by Git:\n- "
            + "\n- ".join(forbidden)
        )
    print(f"Repository hygiene passed: {len(tracked)} tracked paths, 0 forbidden artifacts.")


if __name__ == "__main__":
    main()
