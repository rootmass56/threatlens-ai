
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response


@dataclass(frozen=True)
class RateLimitPolicy:
    requests: int
    window_seconds: int


class InMemoryRateLimiter:
    """Bounded deterministic limiter for the single-process development profile."""

    def __init__(self, *, max_keys: int = 10_000) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be positive.")
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._last_seen: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _prune_stale(self, now: float, *, stale_after: float) -> None:
        stale = [key for key, last_seen in self._last_seen.items() if now - last_seen > stale_after]
        for key in stale:
            self._events.pop(key, None)
            self._last_seen.pop(key, None)

    def _ensure_capacity(self) -> None:
        if len(self._events) < self.max_keys:
            return
        oldest = min(self._last_seen, key=self._last_seen.__getitem__)
        self._events.pop(oldest, None)
        self._last_seen.pop(oldest, None)

    async def allow(self, key: str, policy: RateLimitPolicy) -> tuple[bool, int, int]:
        now = time.monotonic()
        cutoff = now - policy.window_seconds
        async with self._lock:
            self._prune_stale(now, stale_after=max(policy.window_seconds * 2, 120))
            if key not in self._events:
                self._ensure_capacity()
                self._events[key] = deque()
            bucket = self._events[key]
            self._last_seen[key] = now
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= policy.requests:
                retry_after = max(int(policy.window_seconds - (now - bucket[0])) + 1, 1)
                return False, 0, retry_after
            bucket.append(now)
            remaining = max(policy.requests - len(bucket), 0)
            return True, remaining, 0


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid4())
        request.state.request_id = request_id[:128]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._limiter = InMemoryRateLimiter()

    @staticmethod
    def _bucket(path: str) -> tuple[str, RateLimitPolicy]:
        if path.endswith("/auth/login"):
            return "auth-login", RateLimitPolicy(requests=10, window_seconds=60)
        if path.endswith("/auth/refresh"):
            return "auth-refresh", RateLimitPolicy(requests=30, window_seconds=60)
        if "/analyses/upload" in path:
            return "analysis-upload", RateLimitPolicy(requests=20, window_seconds=60)
        if path.endswith("/assistant/query"):
            return "rag-query", RateLimitPolicy(requests=30, window_seconds=60)
        if path.endswith("/assistant/jobs") and path.startswith("/api/"):
            return "rag-job-create", RateLimitPolicy(requests=30, window_seconds=60)
        if "/assistant/jobs/" in path and path.endswith("/cancel"):
            return "rag-job-cancel", RateLimitPolicy(requests=30, window_seconds=60)
        if path.endswith("/rag/knowledge/reindex"):
            return "rag-reindex", RateLimitPolicy(requests=6, window_seconds=60)
        # All ordinary API paths share one source-IP bucket. Dynamic/unknown paths can no
        # longer create independent rate-limit buckets or bypass the generic policy.
        return "api-general", RateLimitPolicy(requests=300, window_seconds=60)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        source = request.client.host if request.client else "unknown"
        bucket_name, policy = self._bucket(request.url.path)
        key = f"{source}:{bucket_name}"
        allowed, remaining, retry_after = await self._limiter.allow(key, policy)
        if not allowed:
            request_id = getattr(request.state, "request_id", None)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "Request rate limit exceeded.",
                        "request_id": request_id,
                    }
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(policy.requests),
                    "X-RateLimit-Remaining": "0",
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(policy.requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
