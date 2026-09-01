from __future__ import annotations

import hashlib
from threading import Lock


class StripedLockRegistry:
    """Bounded in-process keyed locking for single-process correctness gates."""

    def __init__(self, stripes: int = 256) -> None:
        if stripes < 1:
            raise ValueError("stripes must be positive.")
        self._locks = tuple(Lock() for _ in range(stripes))

    @property
    def stripe_count(self) -> int:
        return len(self._locks)

    def lock_for(self, key: str) -> Lock:
        digest = hashlib.sha256(key.encode("utf-8", errors="replace")).digest()
        index = int.from_bytes(digest[:8], "big") % len(self._locks)
        return self._locks[index]
