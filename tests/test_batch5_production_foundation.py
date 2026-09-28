
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.base import Base
from database.models import AnalysisSessionModel, IncidentModel
from jobs.config import JobSettings
from jobs.models import AiJobStatus
from jobs.service import AiJobService, JobCapacityExceeded
from rag.models import RagAnalysisMode, RagQueryResponse, RagResponseStatus, RetrievalDiagnostics

ROOT = Path(__file__).resolve().parents[1]


def _settings() -> JobSettings:
    return JobSettings(
        enabled=True,
        redis_url="redis://localhost:6379/0",
        queue_name="test:jobs",
        worker_block_seconds=1,
        lease_seconds=300,
        heartbeat_seconds=10,
        recovery_interval_seconds=30,
        max_attempts=2,
        retry_delay_seconds=1,
        worker_presence_ttl_seconds=30,
        max_active_jobs=100,
        max_active_jobs_per_actor=5,
    )


@pytest.fixture()
def job_session(tmp_path: Path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with factory() as session:
        analysis = AnalysisSessionModel(
            session_uuid="11111111-1111-4111-8111-111111111111",
            name="Batch 5 job test",
            status="completed",
            source_type="linux_auth",
        )
        session.add(analysis)
        session.flush()
        incident = IncidentModel(
            incident_uuid="22222222-2222-4222-8222-222222222222",
            analysis_session_id=analysis.id,
            title="Test incident",
            severity="High",
            risk_score=90,
            summary="Test incident summary",
        )
        session.add(incident)
        session.commit()
    with factory() as session:
        yield session


def test_batch5_job_model_is_part_of_metadata() -> None:
    assert "ai_investigation_jobs" in Base.metadata.tables
    table = Base.metadata.tables["ai_investigation_jobs"]
    assert {"job_uuid", "status", "lease_expires_at", "result_json"} <= set(table.columns.keys())


def test_batch5_job_creation_and_idempotency(job_session) -> None:
    service = AiJobService(job_session, _settings())
    job, created = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Explain the incident using supported evidence.",
        analysis_mode=RagAnalysisMode.AUTO,
        idempotency_key="request-1",
    )
    job_session.commit()
    assert created is True
    assert job.status == AiJobStatus.QUEUED.value
    assert job.attempts == 0

    existing, created_again = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Explain the incident using supported evidence.",
        analysis_mode="auto",
        idempotency_key="request-1",
    )
    assert created_again is False
    assert existing.job_uuid == job.job_uuid

    with pytest.raises(ValueError, match="Idempotency-Key"):
        service.create(
            incident_uuid="22222222-2222-4222-8222-222222222222",
            actor="admin",
            question="A different request",
            analysis_mode="auto",
            idempotency_key="request-1",
        )


def test_batch5_idempotency_unique_race_recovers_existing_job(
    job_session, monkeypatch
) -> None:
    service = AiJobService(job_session, _settings())
    first, created = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="concurrent-analyst",
        question="Summarize the supported evidence.",
        analysis_mode=RagAnalysisMode.STANDARD,
        idempotency_key="concurrent-request",
    )
    job_session.commit()
    assert created is True

    original_scalar = job_session.scalar
    hidden_first_idempotency_lookup = False

    def race_scalar(statement, *args, **kwargs):
        nonlocal hidden_first_idempotency_lookup
        rendered = str(statement)
        if (
            not hidden_first_idempotency_lookup
            and "ai_investigation_jobs.idempotency_key_hash" in rendered
        ):
            hidden_first_idempotency_lookup = True
            return None
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(job_session, "scalar", race_scalar)

    replay, replay_created = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="concurrent-analyst",
        question="Summarize the supported evidence.",
        analysis_mode=RagAnalysisMode.STANDARD,
        idempotency_key="concurrent-request",
    )

    assert hidden_first_idempotency_lookup is True
    assert replay_created is False
    assert replay.job_uuid == first.job_uuid


def test_batch5_worker_claim_lease_and_completion(job_session) -> None:
    service = AiJobService(job_session, _settings())
    job, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Explain this case.",
        analysis_mode="deep",
    )
    job_session.commit()

    claimed = service.claim(job.job_uuid, worker_id="worker-a")
    assert claimed is not None
    assert claimed.status == AiJobStatus.RUNNING.value
    assert claimed.attempts == 1
    assert claimed.lease_expires_at is not None
    job_session.commit()

    response = RagQueryResponse(
        query_uuid="33333333-3333-4333-8333-333333333333",
        incident_uuid="22222222-2222-4222-8222-222222222222",
        status=RagResponseStatus.ANSWERED,
        assessment="Supported assessment",
        grounding_score=1.0,
        retrieval=RetrievalDiagnostics(
            requested_top_k=3,
            retrieved_count=1,
            accepted_count=1,
            minimum_relevance=0.18,
        ),
        requested_mode=RagAnalysisMode.DEEP,
        resolved_mode=RagAnalysisMode.DEEP,
        served_model="qwen3.5:9b",
        created_at=datetime.now(UTC),
    )
    service.complete(claimed, response)
    job_session.commit()
    refreshed = service.get(job.job_uuid)
    assert refreshed is not None
    assert refreshed.status == AiJobStatus.SUCCEEDED.value
    assert refreshed.result_query_uuid == response.query_uuid
    assert refreshed.result_json["grounding_score"] == 1.0
    assert refreshed.lease_expires_at is None


def test_batch5_worker_claim_waits_for_transient_delivery_lock(
    job_session, monkeypatch
) -> None:
    service = AiJobService(job_session, _settings())
    captured: dict[str, bool] = {}

    def capture_claim(statement, *args, **kwargs):
        del args, kwargs
        captured["skip_locked"] = bool(statement._for_update_arg.skip_locked)
        return None

    monkeypatch.setattr(job_session, "scalar", capture_claim)

    assert service.claim("missing-job", worker_id="worker-a") is None
    assert captured == {"skip_locked": False}


def test_batch5_delivery_reconciliation_includes_orphaned_delivered_jobs(
    job_session
) -> None:
    settings = replace(_settings(), recovery_interval_seconds=30)
    service = AiJobService(job_session, settings)

    pending, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="pending-analyst",
        question="Recover a pending delivery.",
        analysis_mode="standard",
    )
    orphaned, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="orphaned-analyst",
        question="Recover an orphaned delivered job.",
        analysis_mode="standard",
    )
    fresh, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="fresh-analyst",
        question="Leave a fresh delivered job alone.",
        analysis_mode="standard",
    )
    service.mark_enqueued(orphaned)
    orphaned.enqueued_at = datetime.now(UTC) - timedelta(seconds=31)
    service.mark_enqueued(fresh)
    job_session.commit()

    reconciled = service.pending_delivery()
    reconciled_ids = {job.job_uuid for job in reconciled}

    assert pending.job_uuid in reconciled_ids
    assert orphaned.job_uuid in reconciled_ids
    assert fresh.job_uuid not in reconciled_ids


def test_batch5_delivery_update_does_not_overwrite_concurrent_claim(
    job_session
) -> None:
    service = AiJobService(job_session, _settings())
    job, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Preserve a concurrent worker claim.",
        analysis_mode="standard",
    )
    job_session.commit()

    # Keep the queued instance in this session stale while another session
    # claims and commits the same job, matching the API/worker race.
    concurrent_factory = sessionmaker(
        bind=job_session.get_bind(),
        expire_on_commit=False,
    )
    with concurrent_factory() as concurrent_session:
        concurrent_service = AiJobService(concurrent_session, _settings())
        claimed = concurrent_service.claim(job.job_uuid, worker_id="worker-a")
        assert claimed is not None
        concurrent_session.commit()

    assert job.status == AiJobStatus.QUEUED.value
    service.mark_enqueued(job)
    job_session.commit()

    job_session.refresh(job)
    assert job.status == AiJobStatus.RUNNING.value
    assert job.queue_delivery_state == "claimed"
    assert job.worker_id == "worker-a"


def test_batch5_queued_job_can_cancel_but_running_job_cannot(job_session) -> None:
    service = AiJobService(job_session, _settings())
    queued, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Queued cancellation",
        analysis_mode="standard",
    )
    service.cancel(queued, actor="admin")
    assert queued.status == AiJobStatus.CANCELLED.value

    running, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Running cancellation",
        analysis_mode="standard",
    )
    job_session.commit()
    claimed = service.claim(running.job_uuid, worker_id="worker-a")
    assert claimed is not None
    with pytest.raises(RuntimeError, match="cannot be safely interrupted"):
        service.cancel(claimed, actor="admin")


def test_batch5_stale_worker_lease_is_recovered(job_session) -> None:
    service = AiJobService(job_session, _settings())
    job, _ = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="admin",
        question="Recover this job",
        analysis_mode="deep",
    )
    job_session.commit()
    claimed = service.claim(job.job_uuid, worker_id="dead-worker")
    assert claimed is not None
    claimed.lease_expires_at = datetime.now(UTC) - timedelta(seconds=5)
    job_session.commit()
    recovered = service.recover_stale()
    job_session.commit()
    assert [item.job_uuid for item in recovered] == [job.job_uuid]
    assert service.get(job.job_uuid).status == AiJobStatus.QUEUED.value


def test_batch5_migration_and_runtime_dependencies_are_declared() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "e9b5a1300001_add_durable_ai_investigation_jobs.py"
    )
    assert migration.is_file()
    source = migration.read_text(encoding="utf-8")
    assert 'down_revision: str | None = "d4a7c0e51010"' in source
    assert '"ai_investigation_jobs"' in source
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert '"redis==8.1.0"' in pyproject
    assert "redis==8.1.0" in requirements
    assert '"jobs*"' in pyproject


def test_batch5_api_and_worker_surfaces_exist() -> None:
    main = (ROOT / "api" / "main.py").read_text(encoding="utf-8")
    route = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
    worker = (ROOT / "jobs" / "worker.py").read_text(encoding="utf-8")
    assert "jobs.router" in main
    assert '"/incidents/{incident_uuid}/assistant/jobs"' in route
    assert '"/assistant/jobs/{job_uuid}"' in route
    assert '"/assistant/jobs/{job_uuid}/cancel"' in route
    assert "LeaseHeartbeat" in worker
    assert "recover_stale" in worker
    assert "self.queue.heartbeat_worker(self.worker_id)" in worker


def test_batch5_container_stack_is_declared() -> None:
    compose = (ROOT / "deploy/compose/legacy/batch5.yml").read_text(encoding="utf-8")
    for service in ("postgres:", "redis:", "api:", "worker:", "frontend:"):
        assert service in compose
    assert "pgvector/pgvector:pg16" in compose
    assert "THREATLENS_RAG_VECTOR_BACKEND: pgvector" in compose
    assert 'THREATLENS_ASYNC_JOBS_ENABLED: "1"' in compose


def test_batch5_frontend_uses_durable_jobs() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "AiPage.tsx").read_text(encoding="utf-8")
    assert "/assistant/jobs" in source
    assert "QUEUED" in source or "queued" in source
    assert "setInterval" in source
    assert "const reloadHistory = history.reload" in source
    assert "const reloadJobs = jobs.reload" in source
    assert "[jobStatus, jobUuid, reloadHistory, reloadJobs, session]" in source
    assert "[history, jobStatus, jobUuid, jobs, session]" not in source


def test_batch5_job_capacity_backpressure_is_database_authoritative(job_session) -> None:
    settings = replace(_settings(), max_active_jobs=2, max_active_jobs_per_actor=1)
    service = AiJobService(job_session, settings)
    first, created = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="analyst",
        question="Summarize the incident.",
        analysis_mode=RagAnalysisMode.STANDARD,
        idempotency_key="same-request",
    )
    assert created is True

    replay, replay_created = service.create(
        incident_uuid="22222222-2222-4222-8222-222222222222",
        actor="analyst",
        question="Summarize the incident.",
        analysis_mode=RagAnalysisMode.STANDARD,
        idempotency_key="same-request",
    )
    assert replay_created is False
    assert replay.job_uuid == first.job_uuid

    with pytest.raises(JobCapacityExceeded):
        service.create(
            incident_uuid="22222222-2222-4222-8222-222222222222",
            actor="analyst",
            question="Run another investigation.",
            analysis_mode=RagAnalysisMode.STANDARD,
            idempotency_key="another-request",
        )


def test_batch5_cors_allows_idempotent_cross_origin_job_submission() -> None:
    source = (ROOT / "api" / "main.py").read_text(encoding="utf-8")
    assert '"Idempotency-Key"' in source
    assert '"Location"' in source


def test_batch5_openapi_additions_are_protected_and_retained(monkeypatch) -> None:
    monkeypatch.setenv(
        "THREATLENS_JWT_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    from api.main import create_app
    from scripts.openapi_contract import canonicalize_openapi

    schema = canonicalize_openapi(create_app().openapi())
    paths = schema["paths"]
    operations = sum(
        1
        for path_item in paths.values()
        for method, operation in path_item.items()
        if method in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
        and isinstance(operation, dict)
    )
    assert len(paths) >= 48
    assert operations >= 50

    job_paths = {
        "/api/v1/assistant/jobs/health",
        "/api/v1/incidents/{incident_uuid}/assistant/jobs",
        "/api/v1/assistant/jobs/{job_uuid}",
        "/api/v1/assistant/jobs/{job_uuid}/cancel",
    }
    assert job_paths <= set(paths)
    for path in job_paths:
        for operation in paths[path].values():
            if isinstance(operation, dict) and "responses" in operation:
                assert operation.get("security")

    # The live canonical OpenAPI contract above is the release regression authority.
    # It proves every retained Batch-5 durable-job path still exists and is protected.
