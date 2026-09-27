from __future__ import annotations

import logging
import os
import socket
import threading
import time
from contextlib import suppress
from dataclasses import dataclass

from core.observability import configure_structured_logging
from database.session import SessionLocal
from jobs.config import JobSettings, get_job_settings
from jobs.queue import QueueUnavailable, RedisJobQueue
from jobs.service import AiJobService
from rag.runtime import get_rag_runtime

LOGGER = logging.getLogger("threatlens.jobs.worker")


@dataclass
class LeaseHeartbeat:
    settings: JobSettings
    job_uuid: str
    worker_id: str
    queue: RedisJobQueue

    def __post_init__(self) -> None:
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(self.settings.heartbeat_seconds + 2, 5))

    def _run(self) -> None:
        while not self._stop.wait(self.settings.heartbeat_seconds):
            session = SessionLocal()
            try:
                service = AiJobService(session, self.settings)
                if not service.renew_lease(self.job_uuid, worker_id=self.worker_id):
                    session.rollback()
                    return
                session.commit()
            except Exception:
                session.rollback()
                LOGGER.exception("AI job lease heartbeat failed job=%s", self.job_uuid)
            finally:
                session.close()
            try:
                # The main worker loop cannot refresh Redis presence while a
                # local model query is running.  Keep the worker discoverable
                # for the full job duration instead of letting its TTL expire.
                self.queue.heartbeat_worker(self.worker_id)
            except QueueUnavailable as error:
                LOGGER.warning("Worker presence heartbeat failed: %s", error)


def _worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{os.urandom(4).hex()}"


def _deliver_pending(queue: RedisJobQueue, settings: JobSettings) -> None:
    session = SessionLocal()
    try:
        service = AiJobService(session, settings)
        for job in service.pending_delivery(limit=100):
            queue.enqueue(job.job_uuid)
            service.mark_enqueued(job)
        session.commit()
    except QueueUnavailable:
        session.rollback()
    except Exception:
        session.rollback()
        LOGGER.exception("Pending AI job reconciliation failed")
    finally:
        session.close()


def _recover_stale(queue: RedisJobQueue, settings: JobSettings) -> None:
    session = SessionLocal()
    try:
        service = AiJobService(session, settings)
        recovered = service.recover_stale()
        session.commit()
        for job in recovered:
            try:
                queue.enqueue(job.job_uuid)
                session2 = SessionLocal()
                try:
                    row = AiJobService(session2, settings).get(job.job_uuid)
                    if row is not None:
                        AiJobService(session2, settings).mark_enqueued(row)
                    session2.commit()
                finally:
                    session2.close()
            except QueueUnavailable:
                break
    except Exception:
        session.rollback()
        LOGGER.exception("Stale AI job recovery failed")
    finally:
        session.close()


def _process(job_uuid: str, *, worker_id: str, settings: JobSettings, queue: RedisJobQueue) -> None:
    session = SessionLocal()
    heartbeat: LeaseHeartbeat | None = None
    try:
        service = AiJobService(session, settings)
        job = service.claim(job_uuid, worker_id=worker_id)
        session.commit()
        if job is None:
            return
        incident_uuid = job.incident.incident_uuid
        heartbeat = LeaseHeartbeat(settings, job.job_uuid, worker_id, queue)
        heartbeat.start()
        response = get_rag_runtime().query(
            session,
            incident_uuid=incident_uuid,
            actor=job.actor,
            question=job.question,
            analysis_mode=job.analysis_mode,
        )
        service.complete(job, response)
        session.commit()
    except Exception as error:
        session.rollback()
        LOGGER.exception("AI job failed job=%s", job_uuid)
        failure_session = SessionLocal()
        try:
            service = AiJobService(failure_session, settings)
            row = service.get(job_uuid)
            if row is not None and row.status == "running":
                requeue = service.fail(
                    row,
                    code=type(error).__name__.lower()[:128],
                    message=str(error) or "AI job execution failed.",
                )
                failure_session.commit()
                if requeue:
                    time.sleep(settings.retry_delay_seconds)
                    try:
                        queue.enqueue(job_uuid)
                        service.mark_enqueued(row)
                        failure_session.commit()
                    except QueueUnavailable:
                        service.mark_queue_pending(row)
                        failure_session.commit()
        finally:
            failure_session.close()
    finally:
        if heartbeat is not None:
            with suppress(Exception):
                heartbeat.stop()
        session.close()


def main() -> int:
    configure_structured_logging("worker")
    if not os.getenv("THREATLENS_STRUCTURED_LOGGING"):
        logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    settings = get_job_settings()
    if not settings.enabled:
        LOGGER.warning("Asynchronous jobs are disabled; worker exiting.")
        return 0
    queue = RedisJobQueue(settings)
    worker_id = _worker_id()
    last_recovery = 0.0
    LOGGER.info("ThreatLens durable AI worker started worker_id=%s", worker_id)
    while True:
        try:
            queue.heartbeat_worker(worker_id)
            now = time.monotonic()
            if now - last_recovery >= settings.recovery_interval_seconds:
                _recover_stale(queue, settings)
                _deliver_pending(queue, settings)
                last_recovery = now
            job_uuid = queue.dequeue()
            if job_uuid:
                _process(job_uuid, worker_id=worker_id, settings=settings, queue=queue)
        except QueueUnavailable as error:
            LOGGER.warning("Redis unavailable: %s", error)
            time.sleep(min(settings.recovery_interval_seconds, 10))
        except KeyboardInterrupt:
            return 0
        except Exception:
            LOGGER.exception("Worker loop failure")
            time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
