
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

import requests


class EmbeddingProvider(Protocol):
    model_name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...
    def health(self) -> tuple[bool, bool, str | None]: ...


class HashingEmbeddingProvider:
    """Deterministic offline embedding used only for tests/UAT, never claimed as semantic AI."""

    def __init__(self, dimensions: int = 96) -> None:
        self.dimensions = dimensions
        self.model_name = f"threatlens-hashing-{dimensions}d"

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vector = [0.0] * self.dimensions
            for token in re.findall(r"[a-z0-9_.:-]+", text.lower()):
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "big") % self.dimensions
                sign = -1.0 if digest[4] & 1 else 1.0
                vector[index] += sign
            norm = math.sqrt(sum(value * value for value in vector)) or 1.0
            vectors.append([value / norm for value in vector])
        return vectors

    def health(self) -> tuple[bool, bool, str | None]:
        return True, True, None


class OllamaEmbeddingProvider:
    def __init__(
        self,
        *,
        base_url: str,
        model_name: str,
        connect_timeout: int,
        read_timeout: int,
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = (connect_timeout, read_timeout)
        self.health_timeout = (connect_timeout, min(read_timeout, 5))
        self.headers = {"User-Agent": "ThreatLens-RAG/0.12.0"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        response = requests.post(
            f"{self.base_url}/api/embed",
            headers=self.headers,
            json={"model": self.model_name, "input": texts, "truncate": True},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        vectors = payload.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise RuntimeError("Ollama returned an invalid embedding response.")
        return [[float(value) for value in vector] for vector in vectors]

    def health(self) -> tuple[bool, bool, str | None]:
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                headers=self.headers,
                timeout=self.health_timeout,
            )
            response.raise_for_status()
            names = {
                str(item.get("name") or item.get("model") or "")
                for item in response.json().get("models", [])
            }
            if ":" in self.model_name:
                available = self.model_name in names
            else:
                available = self.model_name in {name.split(":", 1)[0] for name in names}
            detail = None
            if not available:
                detail = f"Embedding model {self.model_name!r} is not installed."
            return True, available, detail
        except Exception as error:
            return False, False, str(error)
