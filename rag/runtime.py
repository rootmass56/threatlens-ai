from __future__ import annotations

from functools import lru_cache

from rag.config import get_rag_settings
from rag.service import RagRuntime


@lru_cache(maxsize=1)
def get_rag_runtime() -> RagRuntime:
    return RagRuntime(get_rag_settings())
