
from __future__ import annotations

import json
import os
from pathlib import Path

from api.main import create_app
from scripts.openapi_contract import canonicalize_openapi

ROOT = Path(__file__).resolve().parents[1]
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    os.environ.setdefault(
        "THREATLENS_JWT_SECRET",
        "batch5-static-verifier-0123456789abcdef0123456789abcdef",
    )

    schema = canonicalize_openapi(create_app().openapi())
    paths = schema["paths"]
    operation_count = sum(
        1
        for item in paths.values()
        for method, operation in item.items()
        if method in HTTP_METHODS and isinstance(operation, dict)
    )
    require(len(paths) == 48, f"Expected 48 API paths, found {len(paths)}.")
    require(operation_count == 50, f"Expected 50 API operations, found {operation_count}.")

    batch5_paths = {
        "/api/v1/assistant/jobs/health",
        "/api/v1/incidents/{incident_uuid}/assistant/jobs",
        "/api/v1/assistant/jobs/{job_uuid}",
        "/api/v1/assistant/jobs/{job_uuid}/cancel",
    }
    require(batch5_paths <= set(paths), "One or more Batch-5 AI job API paths are missing.")
    for path in batch5_paths:
        for operation in paths[path].values():
            if isinstance(operation, dict) and "responses" in operation:
                require(bool(operation.get("security")), f"Unprotected Batch-5 operation: {path}")

    snapshot_path = ROOT / "docs" / "openapi_batch5.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    require(schema == snapshot, "Current OpenAPI schema differs from docs/openapi_batch5.json.")

    migration = (
        ROOT / "migrations" / "versions" / "e9b5a1300001_add_durable_ai_investigation_jobs.py"
    ).read_text(encoding="utf-8")
    require('revision: str = "e9b5a1300001"' in migration, "Batch-5 migration revision missing.")
    require('down_revision: str | None = "d4a7c0e51010"' in migration, "Migration chain changed.")
    require('"ai_investigation_jobs"' in migration, "AI job migration table missing.")

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    constraints = (ROOT / "constraints-windows-py311.txt").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for source_name, source in {
        "requirements.txt": requirements,
        "constraints-windows-py311.txt": constraints,
        "pyproject.toml": pyproject,
    }.items():
        require("redis==8.1.0" in source, f"redis pin missing from {source_name}.")
    require('"jobs*"' in pyproject, "jobs package is missing from setuptools discovery.")

    compose = (ROOT / "compose.batch5.yml").read_text(encoding="utf-8")
    for service in ("postgres:", "redis:", "api:", "worker:", "frontend:"):
        require(service in compose, f"Compose service missing: {service}")
    require("pgvector/pgvector:pg16" in compose, "pgvector PostgreSQL image missing.")
    require('command: ["python", "-m", "jobs.worker"]' in compose, "Durable AI worker command missing.")
    require("THREATLENS_AI_MAX_ACTIVE_JOBS" in compose, "Queue capacity budget missing.")

    frontend = (ROOT / "frontend" / "src" / "pages" / "AiPage.tsx").read_text(encoding="utf-8")
    for marker in ("/assistant/jobs/health", "/assistant/jobs", "Idempotency-Key"):
        require(marker in frontend, f"Frontend durable-job marker missing: {marker}")

    print("=" * 78)
    print("THREATLENS BATCH 5 STATIC RELEASE CONTRACT: PASS")
    print("=" * 78)
    print(f"OpenAPI paths      : {len(paths)}")
    print(f"OpenAPI operations : {operation_count}")
    print("Migration head     : e9b5a1300001 (verified by source contract)")
    print("AI jobs            : durable DB lifecycle + Redis transport + worker")
    print("Backpressure       : global + per-actor active-job budgets")
    print("Containers         : frontend/api/worker/postgres/redis declared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
