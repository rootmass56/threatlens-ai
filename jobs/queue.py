from __future__ import annotations

from dataclasses import dataclass

try:
    import redis
except ModuleNotFoundError:  # static/source-only verification environments
    redis = None  # type: ignore[assignment]

from jobs.config import JobSettings


class QueueUnavailable(RuntimeError):
    """Raised when Redis is unavailable."""


@dataclass(frozen=True)
class QueueSnapshot:
    reachable: bool
    pending: int
    workers: int
    detail: str


class RedisJobQueue:
    def __init__(self, settings: JobSettings) -> None:
        self.settings = settings
        if redis is None:
            raise QueueUnavailable("redis-py is not installed in this runtime.")
        self.client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=max(settings.worker_block_seconds + 3, 5),
            health_check_interval=30,
        )
        self.worker_prefix = f"{settings.queue_name}:worker:"

    def _guard(self, operation):
        try:
            return operation()
        except redis.RedisError as error:
            raise QueueUnavailable(str(error)) from error

    def enqueue(self, job_uuid: str) -> bool:
        def op():
            # DB claim semantics make duplicate queue delivery harmless. Avoid common duplicates
            # opportunistically by checking the bounded queue before pushing.
            current = self.client.lrange(self.settings.queue_name, 0, 500)
            if job_uuid in current:
                return False
            self.client.rpush(self.settings.queue_name, job_uuid)
            return True

        return bool(self._guard(op))

    def dequeue(self) -> str | None:
        def op():
            item = self.client.blpop(
                self.settings.queue_name,
                timeout=self.settings.worker_block_seconds,
            )
            return None if item is None else str(item[1])

        return self._guard(op)

    def ping(self) -> bool:
        return bool(self._guard(lambda: self.client.ping()))

    def heartbeat_worker(self, worker_id: str) -> None:
        self._guard(
            lambda: self.client.set(
                f"{self.worker_prefix}{worker_id}",
                "1",
                ex=self.settings.worker_presence_ttl_seconds,
            )
        )

    def snapshot(self) -> QueueSnapshot:
        try:
            pending = int(self.client.llen(self.settings.queue_name))
            workers = sum(1 for _ in self.client.scan_iter(match=f"{self.worker_prefix}*", count=100))
            return QueueSnapshot(True, pending, workers, "Redis queue is reachable.")
        except redis.RedisError as error:
            return QueueSnapshot(False, 0, 0, f"Redis unavailable: {error}")
