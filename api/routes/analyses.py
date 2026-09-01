
from __future__ import annotations

import json
from functools import partial
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from starlette.concurrency import run_in_threadpool

from api.config import SecuritySettings
from api.dependencies import (
    RequireAnalysisCreate,
    RequireAnalysisRead,
    Settings,
)
from api.serialization import dataframe_records, json_safe
from api.uploads import read_limited_upload
from app.application_service import AnalysisExecutionResult, ThreatLensApplicationService
from core.connectors import build_default_connector_registry
from core.pipeline import AnalysisPipelineResult, SourceInput

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _safe_analysis_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned or any(ord(char) < 32 for char in cleaned):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "invalid_analysis_name",
                "message": "Analysis name cannot be blank or contain control characters.",
            },
        )
    return cleaned


def _pipeline_payload(
    pipeline: AnalysisPipelineResult,
    *,
    persisted_metadata: dict[str, Any] | None = None,
) -> dict[str, object]:
    correlation = pipeline.correlation_result
    correlation_payload: dict[str, object] | None = None
    if correlation is not None:
        correlation_payload = {
            "version": correlation.version,
            "policy": correlation.policy.as_dict(),
            "metrics": json_safe(correlation.metrics),
            "deduplicated_alerts": dataframe_records(correlation.deduplicated_alerts_df),
            "entities": dataframe_records(correlation.entities_df),
            "relationships": dataframe_records(correlation.relationships_df),
            "graph": {
                "schema": "threatlens-attack-graph-1.0",
                "nodes": dataframe_records(correlation.graph_nodes_df),
                "edges": dataframe_records(correlation.graph_edges_df),
                "graph_sha256": correlation.graph_sha256,
            },
        }

    parser_statistics = dict(pipeline.combined_parser_statistics())
    source_manifest = list(pipeline.source_manifest)
    connector_ids = list(pipeline.connector_ids)
    loaded_rule_count: int | None = (
        len(pipeline.rule_validation.enabled_rules)
        if pipeline.rule_validation is not None
        else None
    )
    connector_id = pipeline.connector_id

    if persisted_metadata is not None:
        persisted_statistics = dict(persisted_metadata.get("parser_statistics") or {})
        if persisted_statistics:
            parser_statistics = persisted_statistics
            if not source_manifest:
                source_manifest = list(persisted_statistics.get("source_manifest") or [])
            if not connector_ids:
                connector_ids = list(persisted_statistics.get("connector_ids") or [])

        context = dict(persisted_metadata.get("analysis_context") or {})
        if not connector_ids:
            connector_ids = list(
                dict.fromkeys(
                    str(item.get("resolved_connector_id") or "").strip()
                    for item in context.get("sources") or []
                    if str(item.get("resolved_connector_id") or "").strip()
                )
            )
        if connector_id is None:
            connector_id = persisted_metadata.get("connector_id")
        if loaded_rule_count is None:
            raw_count = persisted_metadata.get("loaded_rule_count")
            loaded_rule_count = int(raw_count) if raw_count is not None else None

    return {
        "events": dataframe_records(pipeline.events_df),
        "alerts": dataframe_records(pipeline.alerts_df),
        "incidents": dataframe_records(pipeline.incidents_df),
        "timeline": dataframe_records(pipeline.timeline_df),
        "quarantined": dataframe_records(pipeline.quarantined_dataframe()),
        "source_manifest": json_safe(source_manifest),
        "parser_statistics": json_safe(parser_statistics),
        "connector_ids": connector_ids,
        "connector_id": connector_id,
        "loaded_rule_count": loaded_rule_count,
        "correlation": correlation_payload,
    }


def _execution_payload(result: AnalysisExecutionResult) -> dict[str, object]:
    return {
        "persisted": result.was_persisted,
        "session_uuid": result.session_uuid,
        "duplicate_session_uuid": result.duplicate_session_uuid,
        "pipeline": _pipeline_payload(result.pipeline),
    }


async def _read_uploads(
    files: list[UploadFile],
    settings: SecuritySettings,
) -> list[tuple[str, bytes]]:
    if not files or len(files) > settings.max_upload_files:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "upload_file_count_exceeded",
                "message": f"Upload between 1 and {settings.max_upload_files} files.",
            },
        )
    collected: list[tuple[str, bytes]] = []
    total_bytes = 0
    for upload in files:
        name, content = await read_limited_upload(
            upload,
            maximum_bytes=settings.max_upload_bytes,
        )
        total_bytes += len(content)
        if total_bytes > settings.max_upload_bytes * settings.max_upload_files:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "upload_batch_too_large", "message": "Upload batch is too large."},
            )
        collected.append((name, content))
    return collected


_SOURCE_METADATA_MAX_CHARS = 16_384
_ALLOWED_SOURCE_OPTION_KEYS = frozenset({"analysis_year"})


def _normalize_source_options(value: object) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "invalid_source_metadata",
                "message": "Each source options value must be a JSON object.",
            },
        )
    unknown = sorted(set(value) - _ALLOWED_SOURCE_OPTION_KEYS)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "unsupported_source_option",
                "message": f"Unsupported source option(s): {', '.join(unknown)}.",
            },
        )
    normalized: dict[str, Any] = {}
    if "analysis_year" in value:
        year = value["analysis_year"]
        if isinstance(year, bool) or not isinstance(year, int) or not 2000 <= year <= 2100:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_analysis_year",
                    "message": "analysis_year must be an integer between 2000 and 2100.",
                },
            )
        normalized["analysis_year"] = year
    return normalized


def _parse_source_metadata(
    raw_value: str | None,
    *,
    file_count: int,
) -> list[tuple[str | None, dict[str, Any]]]:
    if raw_value is None or not raw_value.strip():
        return [(None, {}) for _ in range(file_count)]
    if len(raw_value) > _SOURCE_METADATA_MAX_CHARS:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "source_metadata_too_large",
                "message": "Source metadata exceeds the configured safety boundary.",
            },
        )
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "invalid_source_metadata",
                "message": "Source metadata must be valid JSON.",
            },
        ) from error
    if not isinstance(payload, list) or len(payload) != file_count:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "source_metadata_count_mismatch",
                "message": "Source metadata must contain exactly one entry per uploaded file.",
            },
        )

    registered = set(build_default_connector_registry().connector_ids())
    normalized: list[tuple[str | None, dict[str, Any]]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_source_metadata",
                    "message": "Each source metadata entry must be a JSON object.",
                },
            )
        unknown = sorted(set(item) - {"connector_id", "options"})
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "unsupported_source_metadata_field",
                    "message": f"Unsupported source metadata field(s): {', '.join(unknown)}.",
                },
            )
        connector = item.get("connector_id")
        if connector is not None:
            if not isinstance(connector, str) or not connector.strip() or len(connector) > 128:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "code": "invalid_connector_id",
                        "message": (
                            "connector_id must be a non-empty string no longer than 128 characters."
                        ),
                    },
                )
            connector = connector.strip()
            if connector not in registered:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "code": "unknown_connector",
                        "message": "The requested connector is not registered.",
                    },
                )
        normalized.append((connector, _normalize_source_options(item.get("options"))))
    return normalized


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_analysis(
    principal: RequireAnalysisCreate,
    settings: Settings,
    analysis_name: Annotated[str, Form(min_length=1, max_length=255)],
    files: Annotated[list[UploadFile], File()],
    allow_duplicate: Annotated[bool, Form()] = False,
    connector_id: Annotated[str | None, Form(max_length=128)] = None,
    source_metadata: Annotated[str | None, Form(max_length=_SOURCE_METADATA_MAX_CHARS)] = None,
) -> dict[str, object]:
    uploaded = await _read_uploads(files, settings)
    analysis_name = _safe_analysis_name(analysis_name)
    metadata = _parse_source_metadata(source_metadata, file_count=len(uploaded))
    if connector_id and source_metadata:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "conflicting_connector_metadata",
                "message": "Use connector_id or source_metadata, not both.",
            },
        )
    if connector_id:
        if len(uploaded) != 1:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "connector_override_not_allowed",
                    "message": "The legacy connector_id field is supported only for one file; "
                    "use source_metadata for multi-file overrides.",
                },
            )
        registered = set(build_default_connector_registry().connector_ids())
        if connector_id not in registered:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "unknown_connector",
                    "message": "The requested connector is not registered.",
                },
            )
        metadata = [(connector_id, {})]

    service = ThreatLensApplicationService()
    if len(uploaded) == 1:
        name, content = uploaded[0]
        selected_connector, options = metadata[0]
        result = await run_in_threadpool(
            partial(
                service.analyze_and_persist_source,
                analysis_name=analysis_name,
                original_filename=name,
                raw_content=content,
                connector_id=selected_connector,
                connector_options=options,
                actor=principal.username,
                allow_duplicate=allow_duplicate,
            )
        )
    else:
        result = await run_in_threadpool(
            partial(
                service.analyze_and_persist_sources,
                analysis_name=analysis_name,
                sources=[
                    SourceInput(
                        raw_content=content,
                        filename=name,
                        connector_id=metadata[index][0],
                        options=metadata[index][1],
                    )
                    for index, (name, content) in enumerate(uploaded)
                ],
                actor=principal.username,
                allow_duplicate=allow_duplicate,
            )
        )
    return _execution_payload(result)


@router.get("")
def list_analyses(
    principal: RequireAnalysisRead,
    limit: int = 100,
) -> dict[str, object]:
    del principal
    bounded = min(max(limit, 1), 1000)
    frame = ThreatLensApplicationService().get_analysis_history(limit=bounded)
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/{session_uuid}")
def get_analysis(
    session_uuid: str,
    principal: RequireAnalysisRead,
) -> dict[str, object]:
    del principal
    service = ThreatLensApplicationService()
    pipeline = service.load_analysis(session_uuid)
    metadata = service.get_analysis_metadata(session_uuid)
    if pipeline is None or metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "analysis_not_found", "message": "Analysis session was not found."},
        )
    return {
        "session": json_safe(metadata),
        "pipeline": _pipeline_payload(pipeline, persisted_metadata=metadata),
    }


@router.get("/{session_uuid}/correlation")
def get_correlation(
    session_uuid: str,
    principal: RequireAnalysisRead,
) -> dict[str, object]:
    del principal
    service = ThreatLensApplicationService()
    summary = service.get_correlation_summary(session_uuid)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "correlation_not_found", "message": "Correlation data was not found."},
        )
    return {
        "summary": json_safe(summary),
        "entities": dataframe_records(service.get_correlation_entities(session_uuid)),
        "relationships": dataframe_records(service.get_correlation_relationships(session_uuid)),
        "graph": json_safe(service.get_attack_graph(session_uuid)),
    }
