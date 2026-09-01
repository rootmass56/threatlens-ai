from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pandas as pd
import requests

from api.version import THREATLENS_VERSION
from correlation.models import AdvancedCorrelationResult, CorrelationPolicy


class ApiClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id


@dataclass(frozen=True)
class RemoteRuleValidation:
    enabled_rules: tuple[int, ...]


@dataclass(frozen=True)
class RemotePipelineResult:
    events_df: pd.DataFrame
    alerts_df: pd.DataFrame
    incidents_df: pd.DataFrame
    timeline_df: pd.DataFrame
    quarantined_df: pd.DataFrame
    source_manifest: tuple[dict[str, Any], ...]
    parser_statistics: dict[str, Any]
    remote_connector_ids: tuple[str, ...]
    loaded_rule_count: int | None
    correlation_result: AdvancedCorrelationResult | None

    @property
    def event_count(self) -> int:
        return len(self.events_df)

    @property
    def alert_count(self) -> int:
        return len(self.alerts_df)

    @property
    def incident_count(self) -> int:
        return len(self.incidents_df)

    @property
    def quarantined_count(self) -> int:
        persisted = int(self.parser_statistics.get("quarantined_records") or 0)
        return max(len(self.quarantined_df), persisted)

    @property
    def connector_ids(self) -> tuple[str, ...]:
        return self.remote_connector_ids

    @property
    def connector_id(self) -> str | None:
        if not self.remote_connector_ids:
            return None
        return (
            self.remote_connector_ids[0] if len(self.remote_connector_ids) == 1 else "multi_source"
        )

    @property
    def rule_validation(self) -> RemoteRuleValidation:
        return RemoteRuleValidation(tuple(range(self.loaded_rule_count or 0)))

    def quarantined_dataframe(self) -> pd.DataFrame:
        return self.quarantined_df.copy()

    def combined_parser_statistics(self) -> dict[str, Any]:
        return dict(self.parser_statistics)


@dataclass(frozen=True)
class RemoteAnalysisExecutionResult:
    pipeline: RemotePipelineResult
    persisted: bool
    remote_session_uuid: str | None
    duplicate_session_uuid: str | None

    @property
    def was_persisted(self) -> bool:
        return self.persisted

    @property
    def session_uuid(self) -> str | None:
        return self.remote_session_uuid or self.duplicate_session_uuid


TokenUpdateCallback = Callable[[str, str, dict[str, Any]], None]


class ThreatLensApiClient:
    """Authenticated Streamlit-to-FastAPI client preserving the page service contract."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        user: dict[str, Any] | None = None,
        token_update_callback: TokenUpdateCallback | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("THREATLENS_API_URL", "http://127.0.0.1:8000")
        ).rstrip("/")
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user = user or {}
        self._token_update_callback = token_update_callback
        self.timeout_seconds = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": f"ThreatLens-Streamlit/{THREATLENS_VERSION}"})

    @classmethod
    def login(
        cls,
        *,
        username: str,
        password: str,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        client = cls(base_url=base_url)
        response = client._session.post(
            f"{client.base_url}/api/v1/auth/login",
            data={"username": username, "password": password},
            timeout=client.timeout_seconds,
        )
        return client._decode_response(response)

    def logout(self) -> None:
        if self.refresh_token and self.access_token:
            try:
                self._request(
                    "POST",
                    "/api/v1/auth/logout",
                    json={"refresh_token": self.refresh_token},
                    retry_auth=False,
                    expected_status={204},
                )
            except ApiClientError:
                pass

    @staticmethod
    def _decode_response(response: requests.Response) -> Any:
        if response.status_code == 204:
            return None
        try:
            payload = response.json()
        except ValueError as error:
            raise ApiClientError(
                "The API returned an unreadable response.",
                status_code=response.status_code,
                request_id=response.headers.get("X-Request-ID"),
            ) from error
        if response.status_code >= 400:
            envelope = payload.get("error", {}) if isinstance(payload, dict) else {}
            raise ApiClientError(
                str(envelope.get("message") or "API request failed."),
                status_code=response.status_code,
                code=envelope.get("code"),
                request_id=envelope.get("request_id") or response.headers.get("X-Request-ID"),
            )
        return payload

    def _refresh(self) -> None:
        if not self.refresh_token:
            raise ApiClientError("The session has expired. Sign in again.", status_code=401)
        response = self._session.post(
            f"{self.base_url}/api/v1/auth/refresh",
            json={"refresh_token": self.refresh_token},
            timeout=self.timeout_seconds,
        )
        payload = self._decode_response(response)
        self.access_token = payload["access_token"]
        self.refresh_token = payload["refresh_token"]
        self.user = payload["user"]
        if self._token_update_callback:
            self._token_update_callback(
                self.access_token,
                self.refresh_token,
                self.user,
            )

    def _request(
        self,
        method: str,
        path: str,
        *,
        retry_auth: bool = True,
        expected_status: set[int] | None = None,
        **kwargs: Any,
    ) -> Any:
        headers = dict(kwargs.pop("headers", {}))
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        response = self._session.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout_seconds),
            **kwargs,
        )
        if response.status_code == 401 and retry_auth and self.refresh_token:
            self._refresh()
            return self._request(
                method,
                path,
                retry_auth=False,
                expected_status=expected_status,
                **kwargs,
            )
        if expected_status and response.status_code not in expected_status:
            return self._decode_response(response)
        return self._decode_response(response)

    @staticmethod
    def _frame(payload: dict[str, Any]) -> pd.DataFrame:
        return pd.DataFrame(payload.get("items") or [])

    @staticmethod
    def _correlation(payload: dict[str, Any] | None) -> AdvancedCorrelationResult | None:
        if not payload:
            return None
        policy_data = payload.get("policy") or {}
        graph = payload.get("graph") or {}
        return AdvancedCorrelationResult(
            incidents_df=pd.DataFrame(payload.get("incidents") or []),
            deduplicated_alerts_df=pd.DataFrame(payload.get("deduplicated_alerts") or []),
            entities_df=pd.DataFrame(payload.get("entities") or []),
            relationships_df=pd.DataFrame(payload.get("relationships") or []),
            graph_nodes_df=pd.DataFrame(graph.get("nodes") or []),
            graph_edges_df=pd.DataFrame(graph.get("edges") or []),
            metrics=dict(payload.get("metrics") or {}),
            policy=CorrelationPolicy(
                window_minutes=int(policy_data.get("window_minutes", 30)),
                deduplication_window_seconds=int(
                    policy_data.get("deduplication_window_seconds", 60)
                ),
                relationship_threshold=float(policy_data.get("relationship_threshold", 0.66)),
                evidence_relationship_threshold=float(
                    policy_data.get("evidence_relationship_threshold", 0.40)
                ),
                maximum_incident_span_minutes=int(
                    policy_data.get("maximum_incident_span_minutes", 60)
                ),
            ),
            version=str(payload.get("version") or "0.8.0"),
        )

    @classmethod
    def _pipeline(cls, payload: dict[str, Any]) -> RemotePipelineResult:
        return RemotePipelineResult(
            events_df=pd.DataFrame(payload.get("events") or []),
            alerts_df=pd.DataFrame(payload.get("alerts") or []),
            incidents_df=pd.DataFrame(payload.get("incidents") or []),
            timeline_df=pd.DataFrame(payload.get("timeline") or []),
            quarantined_df=pd.DataFrame(payload.get("quarantined") or []),
            source_manifest=tuple(payload.get("source_manifest") or []),
            parser_statistics=dict(payload.get("parser_statistics") or {}),
            remote_connector_ids=tuple(payload.get("connector_ids") or []),
            loaded_rule_count=(
                int(payload["loaded_rule_count"])
                if payload.get("loaded_rule_count") is not None
                else None
            ),
            correlation_result=cls._correlation(payload.get("correlation")),
        )

    def current_user(self) -> dict[str, Any]:
        payload = self._request("GET", "/api/v1/auth/me")
        self.user = payload
        return payload

    def analyze_and_persist_source(
        self,
        *,
        analysis_name: str,
        original_filename: str | None,
        raw_content: str | bytes,
        connector_id: str | None = None,
        connector_options: dict[str, Any] | None = None,
        actor: str = "system",
        allow_duplicate: bool = False,
    ) -> RemoteAnalysisExecutionResult:
        del actor
        content = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
        files = [("files", (original_filename or "telemetry.log", content))]
        data = {
            "analysis_name": analysis_name,
            "allow_duplicate": str(allow_duplicate).lower(),
            "source_metadata": json.dumps(
                [
                    {
                        "connector_id": connector_id,
                        "options": connector_options or {},
                    }
                ],
                separators=(",", ":"),
            ),
        }
        payload = self._request(
            "POST",
            "/api/v1/analyses/upload",
            files=files,
            data=data,
            timeout=180.0,
        )
        return RemoteAnalysisExecutionResult(
            pipeline=self._pipeline(payload["pipeline"]),
            persisted=bool(payload["persisted"]),
            remote_session_uuid=payload.get("session_uuid"),
            duplicate_session_uuid=payload.get("duplicate_session_uuid"),
        )

    def analyze_and_persist_sources(
        self,
        *,
        analysis_name: str,
        sources: list[Any],
        actor: str = "system",
        allow_duplicate: bool = False,
    ) -> RemoteAnalysisExecutionResult:
        del actor
        files = []
        source_metadata: list[dict[str, Any]] = []
        for index, source in enumerate(sources, start=1):
            content = (
                source.raw_content.encode("utf-8")
                if isinstance(source.raw_content, str)
                else source.raw_content
            )
            files.append(("files", (source.filename or f"source-{index}.log", content)))
            source_metadata.append(
                {
                    "connector_id": getattr(source, "connector_id", None),
                    "options": dict(getattr(source, "options", {}) or {}),
                }
            )
        payload = self._request(
            "POST",
            "/api/v1/analyses/upload",
            files=files,
            data={
                "analysis_name": analysis_name,
                "allow_duplicate": str(allow_duplicate).lower(),
                "source_metadata": json.dumps(source_metadata, separators=(",", ":")),
            },
            timeout=180.0,
        )
        return RemoteAnalysisExecutionResult(
            pipeline=self._pipeline(payload["pipeline"]),
            persisted=bool(payload["persisted"]),
            remote_session_uuid=payload.get("session_uuid"),
            duplicate_session_uuid=payload.get("duplicate_session_uuid"),
        )

    def analyze_and_persist_linux_log(self, **kwargs: Any) -> RemoteAnalysisExecutionResult:
        return self.analyze_and_persist_source(
            analysis_name=kwargs["analysis_name"],
            original_filename=kwargs.get("original_filename"),
            raw_content=kwargs.get("raw_content") or kwargs["log_text"],
            connector_id="linux_auth",
            actor=kwargs.get("actor", "system"),
            allow_duplicate=kwargs.get("allow_duplicate", False),
        )

    def get_connector_catalog(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/connectors"))

    def get_connector_diagnostics(
        self,
        *,
        raw_content: str | bytes,
        filename: str | None,
    ) -> pd.DataFrame:
        content = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
        payload = self._request(
            "POST",
            "/api/v1/connectors/diagnose",
            files={"file": (filename or "telemetry.log", content)},
        )
        return self._frame(payload)

    def get_rule_catalog(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/rules"))

    def get_rule_validation(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/rules/validation")

    def get_rule_fixture_results(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/rules/fixtures"))

    def get_rule_quality_summary(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/rules/quality/summary")

    def get_rule_quality_records(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/rules/quality/records"))

    def get_rule_profiles(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/rules/profiles"))

    def get_rule_details(self, rule_id: str) -> dict[str, Any] | None:
        try:
            return self._request("GET", f"/api/v1/rules/{rule_id}")
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def synchronize_attack_catalog(
        self,
        *,
        actor: str = "system",
        force_download: bool = False,
    ) -> dict[str, Any]:
        del actor
        return self._request(
            "POST",
            "/api/v1/attack/synchronize",
            json={"force_download": force_download},
            timeout=600.0,
        )

    def get_attack_catalog_status(self, domain: str = "enterprise-attack"):
        try:
            return self._request("GET", f"/api/v1/attack/catalogues/{domain}")
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def get_attack_catalog_statuses(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/attack/catalogues"))

    def get_attack_techniques(self, domain: str = "enterprise-attack") -> pd.DataFrame:
        return self._frame(self._request("GET", f"/api/v1/attack/catalogues/{domain}/techniques"))

    def get_attack_rule_mappings(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/attack/mappings"))

    def get_attack_object_types(self, domain: str = "enterprise-attack") -> pd.DataFrame:
        return self._frame(self._request("GET", f"/api/v1/attack/catalogues/{domain}/object-types"))

    def get_attack_navigator_json(self) -> bytes:
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = self._session.get(
            f"{self.base_url}/api/v1/attack/navigator",
            headers=headers,
            timeout=self.timeout_seconds,
        )
        if response.status_code == 401 and self.refresh_token:
            self._refresh()
            return self.get_attack_navigator_json()
        if response.status_code >= 400:
            self._decode_response(response)
        return response.content

    def get_correlation_summary(self, session_uuid: str):
        try:
            payload = self._request("GET", f"/api/v1/analyses/{session_uuid}/correlation")
            return payload["summary"]
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def get_correlation_entities(self, session_uuid: str) -> pd.DataFrame:
        payload = self._request("GET", f"/api/v1/analyses/{session_uuid}/correlation")
        return pd.DataFrame(payload.get("entities") or [])

    def get_correlation_relationships(self, session_uuid: str) -> pd.DataFrame:
        payload = self._request("GET", f"/api/v1/analyses/{session_uuid}/correlation")
        return pd.DataFrame(payload.get("relationships") or [])

    def get_attack_graph(self, session_uuid: str):
        try:
            payload = self._request("GET", f"/api/v1/graphs/{session_uuid}")
            return payload.get("graph")
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def get_analysis_history(self, limit: int = 100) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/analyses", params={"limit": limit}))

    def load_analysis(self, session_uuid: str) -> RemotePipelineResult | None:
        try:
            payload = self._request("GET", f"/api/v1/analyses/{session_uuid}")
            return self._pipeline(payload["pipeline"])
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def get_analysis_metadata(self, session_uuid: str):
        try:
            payload = self._request("GET", f"/api/v1/analyses/{session_uuid}")
            return payload.get("session")
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def get_incident_queue(self, *, status: str | None = None, limit: int = 250) -> pd.DataFrame:
        params = {"limit": limit}
        if status:
            params["status_filter"] = status
        return self._frame(self._request("GET", "/api/v1/incidents", params=params))

    def get_incident_details(self, incident_uuid: str):
        try:
            return self._request("GET", f"/api/v1/incidents/{incident_uuid}")
        except ApiClientError as error:
            if error.status_code == 404:
                return None
            raise

    def update_incident(
        self,
        *,
        incident_uuid: str,
        status: str,
        assignee: str | None,
        priority: str | None,
        actor: str,
    ) -> None:
        del actor
        self._request(
            "PATCH",
            f"/api/v1/incidents/{incident_uuid}/workflow",
            json={"status": status, "assignee": assignee or None, "priority": priority},
        )

    def add_incident_note(self, *, incident_uuid: str, author: str, note: str) -> str:
        del author
        payload = self._request(
            "POST",
            f"/api/v1/incidents/{incident_uuid}/notes",
            json={"note": note},
        )
        return str(payload["note_id"])

    def register_incident_evidence(
        self,
        *,
        incident_uuid: str,
        evidence_type: str,
        description: str,
        source_reference: str | None,
        sha256: str | None,
        actor: str,
    ) -> str:
        del actor
        payload = self._request(
            "POST",
            f"/api/v1/incidents/{incident_uuid}/evidence",
            json={
                "evidence_type": evidence_type,
                "description": description,
                "source_reference": source_reference or None,
                "sha256": sha256 or None,
            },
        )
        return str(payload["evidence_uuid"])

    def get_audit_logs(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 500,
    ) -> pd.DataFrame:
        params: dict[str, Any] = {"limit": limit}
        if entity_type:
            params["entity_type"] = entity_type
        if entity_id:
            params["entity_id"] = entity_id
        return self._frame(self._request("GET", "/api/v1/audit", params=params))

    def get_incident_report_pdf(
        self,
        session_uuid: str,
    ) -> tuple[bytes, str, str | None]:
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = self._session.get(
            f"{self.base_url}/api/v1/reports/analyses/{session_uuid}/incident.pdf",
            headers=headers,
            timeout=180.0,
        )
        if response.status_code == 401 and self.refresh_token:
            self._refresh()
            return self.get_incident_report_pdf(session_uuid)
        if response.status_code >= 400:
            self._decode_response(response)
        disposition = response.headers.get("Content-Disposition", "")
        filename = f"threatlens_incident_report_{session_uuid}.pdf"
        marker = 'filename="'
        if marker in disposition:
            filename = disposition.split(marker, 1)[1].split('"', 1)[0]
        return response.content, filename, response.headers.get("X-Content-SHA256")

    def get_persistent_metrics(self) -> dict[str, Any]:
        history = self.get_analysis_history(limit=1000)
        incidents = self.get_incident_queue(limit=1000)
        metrics = {
            "total_analyses": len(history),
            "total_events": int(history["events"].sum()) if "events" in history else 0,
            "total_alerts": int(history["alerts"].sum()) if "alerts" in history else 0,
            "total_incidents": int(history["incidents"].sum()) if "incidents" in history else 0,
            "total_quarantined": (
                int(history["quarantined"].sum()) if "quarantined" in history else 0
            ),
            "open_incidents": 0,
            "critical_incidents": 0,
            "investigating_incidents": 0,
            "resolved_incidents": 0,
            "false_positive_incidents": 0,
        }
        if not incidents.empty:
            status_series = incidents["status"]
            metrics.update(
                {
                    "open_incidents": int((status_series == "open").sum()),
                    "critical_incidents": int((incidents["severity"] == "Critical").sum()),
                    "investigating_incidents": int((status_series == "investigating").sum()),
                    "resolved_incidents": int((status_series == "resolved").sum()),
                    "false_positive_incidents": int((status_series == "false_positive").sum()),
                }
            )
        return metrics

    def list_users(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/users"))

    def list_roles(self) -> pd.DataFrame:
        return self._frame(self._request("GET", "/api/v1/users/roles"))

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/users", json=payload)

    def update_user(self, user_uuid: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("PATCH", f"/api/v1/users/{user_uuid}", json=payload)

    def get_rag_health(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/rag/health")

    def get_rag_knowledge_status(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/rag/knowledge/status")

    def reindex_rag_knowledge(self, *, force: bool = False) -> dict[str, Any]:
        return self._request("POST", "/api/v1/rag/knowledge/reindex", json={"force": force})

    def query_incident_assistant(
        self,
        incident_uuid: str,
        question: str,
        *,
        analysis_mode: str = "auto",
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/v1/incidents/{incident_uuid}/assistant/query",
            json={"question": question, "analysis_mode": analysis_mode},
            timeout=max(
                self.timeout_seconds,
                float(os.getenv("THREATLENS_RAG_API_TIMEOUT_SECONDS", "1320")),
            ),
        )

    def get_incident_assistant_history(
        self, incident_uuid: str, *, limit: int = 50
    ) -> pd.DataFrame:
        payload = self._request(
            "GET",
            f"/api/v1/incidents/{incident_uuid}/assistant/history",
            params={"limit": limit},
        )
        return pd.DataFrame(payload.get("items") or [])

    def security_status(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/system/security")

    def protected_openapi(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/system/openapi")
