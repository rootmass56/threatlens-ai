from __future__ import annotations

from pathlib import Path

from scripts.release_inventory import canonical_release_bytes_from_data
from scripts.verify_repository_hygiene import _forbidden_tracked

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_release_hash_input_is_newline_portable() -> None:
    lf, lf_mode = canonical_release_bytes_from_data(b"alpha\nbeta\n")
    crlf, crlf_mode = canonical_release_bytes_from_data(b"alpha\r\nbeta\r\n")
    assert lf == crlf == b"alpha\nbeta\n"
    assert lf_mode == crlf_mode == "utf8-lf"


def test_repository_hygiene_rejects_tracked_release_archives() -> None:
    assert _forbidden_tracked("ThreatLensAI_v0.9.1_FINAL.zip")
    assert _forbidden_tracked("releases/ThreatLensAI_v0.9.2_FINAL.zip")


def test_gitignore_excludes_root_release_archives() -> None:
    lines = (ROOT_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/ThreatLensAI_v*.zip" in lines


def test_upload_page_has_no_stale_v06_milestone_labels() -> None:
    source = (ROOT_DIR / "app" / "pages" / "upload.py").read_text(encoding="utf-8")
    assert "ThreatLens v0.6 accepts" not in source
    assert "ThreatLens v0.6 Multi-Source Demo" not in source
