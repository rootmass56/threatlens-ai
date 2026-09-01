
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from api.rbac import ROLE_DEFINITIONS
from rag.models import RagAnalysisMode


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TokenPairResponse(StrictModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int
    user: dict[str, Any]


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=32, max_length=4096)


class LogoutRequest(StrictModel):
    refresh_token: str = Field(min_length=32, max_length=4096)


class UserCreateRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=255)
    email: EmailStr | None = None
    password: str = Field(min_length=12, max_length=256)
    roles: list[str] = Field(min_length=1, max_length=6)

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, value: list[str]) -> list[str]:
        normalized = [role.strip().lower() for role in value]
        if len(normalized) != len(set(normalized)):
            raise ValueError("Roles cannot contain duplicates.")
        invalid = sorted(set(normalized) - set(ROLE_DEFINITIONS))
        if invalid:
            raise ValueError("Unknown roles: " + ", ".join(invalid))
        return normalized


class UserUpdateRequest(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    email: EmailStr | None = None
    is_active: bool | None = None
    roles: list[str] | None = Field(default=None, min_length=1, max_length=6)
    password: str | None = Field(default=None, min_length=12, max_length=256)
    unlock: bool = False
    revoke_sessions: bool = False

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return UserCreateRequest.validate_roles(value)


class IncidentWorkflowRequest(StrictModel):
    status: str | None = Field(
        default=None,
        pattern=r"^(open|investigating|contained|resolved|false_positive)$",
    )
    assignee: str | None = Field(default=None, max_length=64)
    priority: str | None = Field(default=None, pattern=r"^P[1-4]$")

    @model_validator(mode="after")
    def require_at_least_one_change(self) -> IncidentWorkflowRequest:
        if not self.model_fields_set:
            raise ValueError("At least one workflow field must be supplied.")
        if "status" in self.model_fields_set and self.status is None:
            raise ValueError("status cannot be null when supplied.")
        if "priority" in self.model_fields_set and self.priority is None:
            raise ValueError("priority cannot be null when supplied.")
        return self


class InvestigationNoteRequest(StrictModel):
    note: str = Field(min_length=1, max_length=10_000)


class EvidenceRequest(StrictModel):
    evidence_type: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=10_000)
    source_reference: str | None = Field(default=None, max_length=1024)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class AttackSyncRequest(StrictModel):
    force_download: bool = False


class HealthResponse(StrictModel):
    status: str
    version: str
    database: str | None = None
    timestamp: datetime


class ErrorEnvelope(StrictModel):
    error: dict[str, Any]


class Pagination(StrictModel):
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class AnalysisUploadMetadata(StrictModel):
    analysis_name: str = Field(min_length=1, max_length=255)
    allow_duplicate: bool = False
    connector_id: str | None = Field(default=None, max_length=128)

    @field_validator("analysis_name")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("Analysis name cannot contain control characters.")
        return value


class RagQueryRequest(StrictModel):
    question: str = Field(min_length=1, max_length=2000)
    analysis_mode: RagAnalysisMode = RagAnalysisMode.AUTO


class RagReindexRequest(StrictModel):
    force: bool = False
