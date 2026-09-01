
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Response, UploadFile, status

from api.dependencies import (
    RequireAnalysisRead,
    RequireAttackRead,
    RequireAttackSync,
    RequireGraphRead,
    RequireRuleRead,
    Settings,
)
from api.schemas import AttackSyncRequest
from api.serialization import dataframe_records, json_safe
from api.uploads import read_limited_upload
from app.application_service import ThreatLensApplicationService

router = APIRouter(tags=["catalogues"])


@router.get("/connectors")
def connectors(principal: RequireAnalysisRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_connector_catalog()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.post("/connectors/diagnose")
async def connector_diagnostics(
    principal: RequireAnalysisRead,
    settings: Settings,
    file: Annotated[UploadFile, File(...)],
) -> dict[str, object]:
    del principal
    filename, content = await read_limited_upload(
        file,
        maximum_bytes=settings.max_upload_bytes,
    )
    frame = ThreatLensApplicationService().get_connector_diagnostics(
        raw_content=content,
        filename=filename,
    )
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/rules")
def rules(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_rule_catalog()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/rules/validation")
def rule_validation(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    return json_safe(ThreatLensApplicationService().get_rule_validation())


@router.get("/rules/fixtures")
def rule_fixtures(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_rule_fixture_results()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/rules/quality/summary")
def rule_quality_summary(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    return json_safe(ThreatLensApplicationService().get_rule_quality_summary())


@router.get("/rules/quality/records")
def rule_quality_records(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_rule_quality_records()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/rules/profiles")
def rule_profiles(principal: RequireRuleRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_rule_profiles()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/rules/{rule_id}")
def rule_details(rule_id: str, principal: RequireRuleRead) -> dict[str, object]:
    del principal
    payload = ThreatLensApplicationService().get_rule_details(rule_id)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "rule_not_found", "message": "Detection rule was not found."},
        )
    return json_safe(payload)


@router.get("/attack/catalogues")
def attack_catalogues(principal: RequireAttackRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_attack_catalog_statuses()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/attack/catalogues/{domain}")
def attack_catalogue(domain: str, principal: RequireAttackRead) -> dict[str, object]:
    del principal
    payload = ThreatLensApplicationService().get_attack_catalog_status(domain)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "attack_catalogue_not_found", "message": "ATT&CK catalogue not found."},
        )
    return json_safe(payload)


@router.get("/attack/catalogues/{domain}/techniques")
def attack_techniques(domain: str, principal: RequireAttackRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_attack_techniques(domain)
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/attack/catalogues/{domain}/object-types")
def attack_object_types(domain: str, principal: RequireAttackRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_attack_object_types(domain)
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/attack/mappings")
def attack_mappings(principal: RequireAttackRead) -> dict[str, object]:
    del principal
    frame = ThreatLensApplicationService().get_attack_rule_mappings()
    return {"items": dataframe_records(frame), "count": len(frame)}


@router.get("/attack/navigator")
def attack_navigator(principal: RequireAttackRead) -> Response:
    del principal
    return Response(
        ThreatLensApplicationService().get_attack_navigator_json(),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="threatlens_attack_navigator.json"'},
    )


@router.post("/attack/synchronize")
def synchronize_attack(
    payload: AttackSyncRequest,
    principal: RequireAttackSync,
) -> dict[str, object]:
    return json_safe(
        ThreatLensApplicationService().synchronize_attack_catalog(
            actor=principal.username,
            force_download=payload.force_download,
        )
    )


@router.get("/graphs/{session_uuid}")
def graph(session_uuid: str, principal: RequireGraphRead) -> dict[str, object]:
    del principal
    service = ThreatLensApplicationService()
    graph_payload = service.get_attack_graph(session_uuid)
    summary = service.get_correlation_summary(session_uuid)
    if graph_payload is None or summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "graph_not_found", "message": "Attack graph was not found."},
        )
    return {
        "summary": json_safe(summary),
        "graph": json_safe(graph_payload),
        "entities": dataframe_records(service.get_correlation_entities(session_uuid)),
        "relationships": dataframe_records(service.get_correlation_relationships(session_uuid)),
    }
