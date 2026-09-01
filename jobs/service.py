from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database.models import AiInvestigationJobModel, IncidentModel
from jobs.config import JobSettings
from jobs.models import AiJobStatus
from rag.models import RagAnalysisMode, RagQueryResponse


class JobCapacityExceeded(RuntimeError):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AiJobService:
    def __init__(self, session: Session, settings: JobSettings) -> None:
        self.session = session
        self.settings = settings

    def get(self, job_uuid: str) -> AiInvestigationJobModel | None:
        return self.session.scalar(
            select(AiInvestigationJobModel).where(AiInvestigationJobModel.job_uuid == job_uuid)
        )

    def _incident(self, incident_uuid: str) -> IncidentModel:
        incident = self.session.scalar(
            select(IncidentModel).where(IncidentModel.incident_uuid == incident_uuid)
        )
        if incident is None:
            raise LookupError("Incident was not found.")
        return incident

    def create(
        self,
        *,
        incident_uuid: str,
        actor: str,
        question: str,
        analysis_mode: RagAnalysisMode | str,
        idempotency_key: str | None = None,
        max_question_chars: int = 2000,
    ) -> tuple[AiInvestigationJobModel, bool]:
        question = " ".join(str(question).split()).strip()
        if not question:
            raise ValueError("Question cannot be empty.")
        if len(question) > max_question_chars:
            raise ValueError(f"Question exceeds {max_question_chars} characters.")
        mode = RagAnalysisMode(analysis_mode).value
        incident = self._incident(incident_uuid)
        fingerprint = _sha(
            json.dumps(
                {
                    "incident_uuid": incident_uuid,
                    "actor": actor,
                    "question": question,
                    "analysis_mode": mode,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        key_hash = _sha(f"{actor}:{idempotency_key}") if idempotency_key else None
        if key_hash:
            existing = self.session.scalar(
                select(AiInvestigationJobModel).where(
                    AiInvestigationJobModel.idempotency_key_hash == key_hash
                )
            )
            if existing is not None:
                if existing.request_fingerprint != fingerprint:
                    raise ValueError("Idempotency-Key was already used for a different request.")
                return existing, False

        active_states = [AiJobStatus.QUEUED.value, AiJobStatus.RUNNING.value]
        global_active = int(
            self.session.scalar(
                select(func.count(AiInvestigationJobModel.id)).where(
                    AiInvestigationJobModel.status.in_(active_states)
                )
            )
            or 0
        )
        actor_active = int(
            self.session.scalar(
                select(func.count(AiInvestigationJobModel.id)).where(
                    AiInvestigationJobModel.status.in_(active_states),
                    AiInvestigationJobModel.actor == actor,
                )
            )
            or 0
        )
        if global_active >= self.settings.max_active_jobs:
            raise JobCapacityExceeded("The global durable AI job capacity is currently full.")
        if actor_active >= self.settings.max_active_jobs_per_actor:
            raise JobCapacityExceeded("This analyst already has the maximum number of active AI jobs.")

        job = AiInvestigationJobModel(
            job_uuid=str(uuid4()),
            incident_id=incident.id,
            actor=actor,
            question=question,
            question_sha256=_sha(question),
            analysis_mode=mode,
            status=AiJobStatus.QUEUED.value,
            idempotency_key_hash=key_hash,
            request_fingerprint=fingerprint,
            attempts=0,
            max_attempts=self.settings.max_attempts,
            queue_delivery_state="pending",
            result_json={},
        )
        self.session.add(job)
        self.session.flush()
        return job, True

    def list_for_incident(self, incident_uuid: str, *, limit: int = 50) -> list[AiInvestigationJobModel]:
        incident = self._incident(incident_uuid)
        return list(
            self.session.scalars(
                select(AiInvestigationJobModel)
                .where(AiInvestigationJobModel.incident_id == incident.id)
                .order_by(AiInvestigationJobModel.created_at.desc())
                .limit(min(max(limit, 1), 250))
            ).all()
        )

    def mark_enqueued(self, job: AiInvestigationJobModel) -> None:
        if job.status == AiJobStatus.QUEUED.value:
            job.queue_delivery_state = "delivered"
            job.enqueued_at = _utcnow()

    def mark_queue_pending(self, job: AiInvestigationJobModel) -> None:
        if job.status == AiJobStatus.QUEUED.value:
            job.queue_delivery_state = "pending"

    def claim(self, job_uuid: str, *, worker_id: str) -> AiInvestigationJobModel | None:
        stmt = (
            select(AiInvestigationJobModel)
            .where(
                AiInvestigationJobModel.job_uuid == job_uuid,
                AiInvestigationJobModel.status == AiJobStatus.QUEUED.value,
            )
            .with_for_update(skip_locked=True)
        )
        job = self.session.scalar(stmt)
        if job is None:
            return None
        if job.attempts >= job.max_attempts:
            job.status = AiJobStatus.FAILED.value
            job.error_code = "retry_budget_exhausted"
            job.error_message = "Durable AI job exhausted its retry budget before claim."
            job.completed_at = _utcnow()
            job.queue_delivery_state = "complete"
            return None
        now = _utcnow()
        job.status = AiJobStatus.RUNNING.value
        job.attempts += 1
        job.worker_id = worker_id
        job.started_at = job.started_at or now
        job.lease_expires_at = now + timedelta(seconds=self.settings.lease_seconds)
        job.queue_delivery_state = "claimed"
        job.error_code = None
        job.error_message = None
        self.session.flush()
        return job

    def renew_lease(self, job_uuid: str, *, worker_id: str) -> bool:
        job = self.session.scalar(
            select(AiInvestigationJobModel).where(
                AiInvestigationJobModel.job_uuid == job_uuid,
                AiInvestigationJobModel.status == AiJobStatus.RUNNING.value,
                AiInvestigationJobModel.worker_id == worker_id,
            )
        )
        if job is None:
            return False
        job.lease_expires_at = _utcnow() + timedelta(seconds=self.settings.lease_seconds)
        self.session.flush()
        return True

    def complete(self, job: AiInvestigationJobModel, response: RagQueryResponse) -> None:
        if job.status != AiJobStatus.RUNNING.value:
            raise RuntimeError("Only a running AI job can be completed.")
        job.status = AiJobStatus.SUCCEEDED.value
        job.result_query_uuid = response.query_uuid
        job.result_json = response.model_dump(mode="json")
        job.queue_delivery_state = "complete"
        job.lease_expires_at = None
        job.completed_at = _utcnow()
        job.error_code = None
        job.error_message = None

    def fail(self, job: AiInvestigationJobModel, *, code: str, message: str) -> bool:
        """Record a failure. Return True when the job should be requeued."""
        job.error_code = code[:128]
        job.error_message = message[:8000]
        job.lease_expires_at = None
        job.worker_id = None
        if job.attempts < job.max_attempts:
            job.status = AiJobStatus.QUEUED.value
            job.queue_delivery_state = "pending"
            return True
        job.status = AiJobStatus.FAILED.value
        job.queue_delivery_state = "complete"
        job.completed_at = _utcnow()
        return False

    def cancel(self, job: AiInvestigationJobModel, *, actor: str) -> None:
        del actor
        if job.status == AiJobStatus.RUNNING.value:
            raise RuntimeError("A running local-model job cannot be safely interrupted.")
        if job.status == AiJobStatus.QUEUED.value:
            job.status = AiJobStatus.CANCELLED.value
            job.queue_delivery_state = "complete"
            job.completed_at = _utcnow()
            job.lease_expires_at = None

    def pending_delivery(self, *, limit: int = 100) -> list[AiInvestigationJobModel]:
        return list(
            self.session.scalars(
                select(AiInvestigationJobModel)
                .where(
                    AiInvestigationJobModel.status == AiJobStatus.QUEUED.value,
                    AiInvestigationJobModel.queue_delivery_state == "pending",
                )
                .order_by(AiInvestigationJobModel.created_at.asc())
                .limit(limit)
            ).all()
        )

    def recover_stale(self) -> list[AiInvestigationJobModel]:
        now = _utcnow()
        jobs = list(
            self.session.scalars(
                select(AiInvestigationJobModel)
                .where(
                    AiInvestigationJobModel.status == AiJobStatus.RUNNING.value,
                    AiInvestigationJobModel.lease_expires_at.is_not(None),
                    AiInvestigationJobModel.lease_expires_at < now,
                )
                .with_for_update(skip_locked=True)
            ).all()
        )
        recovered: list[AiInvestigationJobModel] = []
        for job in jobs:
            job.worker_id = None
            job.lease_expires_at = None
            if job.attempts >= job.max_attempts:
                job.status = AiJobStatus.FAILED.value
                job.queue_delivery_state = "complete"
                job.error_code = "worker_lease_expired"
                job.error_message = "Worker lease expired after the retry budget was exhausted."
                job.completed_at = now
            else:
                job.status = AiJobStatus.QUEUED.value
                job.queue_delivery_state = "pending"
                job.error_code = "worker_lease_expired"
                job.error_message = "Worker lease expired; job recovered for another bounded attempt."
                recovered.append(job)
        self.session.flush()
        return recovered

    @staticmethod
    def serialize(job: AiInvestigationJobModel) -> dict[str, object]:
        return {
            "job_uuid": job.job_uuid,
            "status": job.status,
            "actor": job.actor,
            "question": job.question,
            "analysis_mode": job.analysis_mode,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
            "worker_id": job.worker_id,
            "queue_delivery_state": job.queue_delivery_state,
            "result_query_uuid": job.result_query_uuid,
            "result": job.result_json or None,
            "error_code": job.error_code,
            "error_message": job.error_message,
            "lease_expires_at": job.lease_expires_at,
            "enqueued_at": job.enqueued_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        }
