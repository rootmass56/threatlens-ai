from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path
from typing import Final

ROOT_DIR: Final[Path] = Path(__file__).resolve().parents[1]
CURRENT_MANIFEST: Final[str] = "release/RELEASE_MANIFEST_v0.14.0.json"

_EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".idea",
        ".vscode",
        "__pycache__",
        "htmlcov",
        "node_modules",
    }
)
_EXCLUDED_FILE_PATTERNS: Final[tuple[str, ...]] = (
    "*.pyc",
    "*.pyo",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.sqlite",
    "*.sqlite3",
    "*.zip",
    "*.tsbuildinfo",
    ".coverage",
    ".DS_Store",
    "Thumbs.db",
)


def _relative(path: Path) -> str:
    return path.relative_to(ROOT_DIR).as_posix()


def is_release_relative_path(relative: str) -> bool:
    """Return whether a relative source-tree path belongs in the immutable release."""

    relative = relative.replace("\\", "/")
    parts = Path(relative).parts
    if relative == CURRENT_MANIFEST:
        return False
    if any(part in _EXCLUDED_DIR_NAMES or part.endswith(".egg-info") for part in parts):
        return False
    if relative == ".env" or (relative.startswith(".env.") and relative != ".env.example"):
        return False
    if relative == ".streamlit/secrets.toml":
        return False
    if relative == "data/bootstrap_admin_credentials.txt":
        return False
    if (
        relative.startswith("data/reports/")
        or relative.startswith("data/uat/")
        or relative.startswith("data/parsed/")
        or relative.startswith("data/rag/")
        or relative.startswith("data/dependency_attestation/")
    ):
        return False
    if relative.startswith("logs/"):
        return False
    if relative.startswith("frontend/dist/"):
        return False
    if relative.startswith("exports/openapi/") or relative.startswith("exports/attack/"):
        return False
    if relative.startswith("data/attack/"):
        name = Path(relative).name
        if fnmatch.fnmatch(name, "*-attack-*.json") or fnmatch.fnmatch(name, "*.metadata.json"):
            return False
    return not any(
        fnmatch.fnmatch(Path(relative).name, pattern) for pattern in _EXCLUDED_FILE_PATTERNS
    )


def is_release_file(path: Path) -> bool:
    """Return whether a filesystem path belongs in the immutable source release."""

    return path.is_file() and is_release_relative_path(_relative(path))


def release_paths() -> list[Path]:
    return sorted(
        (path for path in ROOT_DIR.rglob("*") if is_release_file(path)),
        key=lambda path: _relative(path),
    )


def canonical_release_bytes_from_data(data: bytes) -> tuple[bytes, str]:
    """Normalize UTF-8 text newlines so hashes survive Git EOL transformations."""

    if b"\x00" in data:
        return data, "binary"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, "binary"
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return normalized, "utf8-lf"


def canonical_release_bytes(path: Path) -> tuple[bytes, str]:
    return canonical_release_bytes_from_data(path.read_bytes())


def sha256_file(path: Path) -> str:
    data, _ = canonical_release_bytes(path)
    return hashlib.sha256(data).hexdigest()


def file_record(path: Path) -> dict[str, object]:
    data, content_mode = canonical_release_bytes(path)
    return {
        "path": _relative(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "content_mode": content_mode,
    }
