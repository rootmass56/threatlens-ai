from __future__ import annotations

import math

MIB = 1024 * 1024
_STREAMLIT_MB = 1_000_000


def streamlit_upload_limit_mb(max_file_bytes: int) -> int:
    """Return a widget MB cap that never rejects a file accepted by the API byte limit."""

    return max(1, math.ceil(max(int(max_file_bytes), 1) / _STREAMLIT_MB))


def enforce_file_size(size_bytes: int, max_file_bytes: int, *, label: str) -> None:
    """Fail closed when a browser-side file exceeds the authoritative API byte limit."""

    if size_bytes <= 0:
        raise ValueError(f"{label} is empty.")
    if size_bytes > max_file_bytes:
        limit_mib = max_file_bytes / MIB
        raise ValueError(f"{label} exceeds the {limit_mib:.1f} MiB file limit.")
