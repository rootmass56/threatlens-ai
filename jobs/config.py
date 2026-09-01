from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int = 1) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    parsed = int(value)
    return max(parsed, minimum)


@dataclass(frozen=True)
class JobSettings:
    enabled: bool
    redis_url: str
    queue_name: str
    worker_block_seconds: int
    lease_seconds: int
    heartbeat_seconds: int
    recovery_interval_seconds: int
    max_attempts: int
    retry_delay_seconds: int
    worker_presence_ttl_seconds: int
    max_active_jobs: int
    max_active_jobs_per_actor: int


@lru_cache(maxsize=1)
def get_job_settings() -> JobSettings:
    return JobSettings(
        enabled=_bool("THREATLENS_ASYNC_JOBS_ENABLED", False),
        redis_url=os.getenv("THREATLENS_REDIS_URL", "redis://127.0.0.1:6379/0").strip(),
        queue_name=os.getenv("THREATLENS_AI_QUEUE_NAME", "threatlens:ai:jobs").strip(),
        worker_block_seconds=_int("THREATLENS_AI_WORKER_BLOCK_SECONDS", 5),
        lease_seconds=_int("THREATLENS_AI_JOB_LEASE_SECONDS", 1800),
        heartbeat_seconds=_int("THREATLENS_AI_JOB_HEARTBEAT_SECONDS", 30),
        recovery_interval_seconds=_int("THREATLENS_AI_JOB_RECOVERY_INTERVAL_SECONDS", 60),
        max_attempts=_int("THREATLENS_AI_JOB_MAX_ATTEMPTS", 2),
        retry_delay_seconds=_int("THREATLENS_AI_JOB_RETRY_DELAY_SECONDS", 5),
        worker_presence_ttl_seconds=_int("THREATLENS_AI_WORKER_PRESENCE_TTL_SECONDS", 90),
        max_active_jobs=_int("THREATLENS_AI_MAX_ACTIVE_JOBS", 100),
        max_active_jobs_per_actor=_int("THREATLENS_AI_MAX_ACTIVE_JOBS_PER_ACTOR", 5),
    )
