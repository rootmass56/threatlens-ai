
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictRagModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RagAnalysisMode(StrEnum):
    AUTO = "auto"
    STANDARD = "standard"
    DEEP = "deep"


class RagResponseStatus(StrEnum):
    ANSWERED = "answered"
    PARTIALLY_SUPPORTED = "partially_supported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    OUT_OF_SCOPE = "out_of_scope"
    RETRIEVAL_FAILED = "retrieval_failed"
    LLM_UNAVAILABLE = "llm_unavailable"
    DISABLED = "disabled"


class RagRoutingDecision(StrictRagModel):
    requested_mode: RagAnalysisMode = RagAnalysisMode.AUTO
    resolved_mode: RagAnalysisMode
    requested_model: str
    complexity_score: int = Field(ge=0)
    reasons: list[str] = Field(default_factory=list, max_length=16)


class RagModelProfileHealth(StrictRagModel):
    mode: RagAnalysisMode
    profile_name: str
    model: str
    reachable: bool
    available: bool
    num_ctx: int
    num_predict: int
    read_timeout_seconds: int
    detail: str | None = None


class RagQueryPlan(StrictRagModel):
    attack_ids: list[str] = Field(default_factory=list, max_length=32)
    exact_source_ids: list[str] = Field(default_factory=list, max_length=64)
    requires_incident_evidence: bool = True
    requires_governed_knowledge: bool = False
    requires_source_separation: bool = False
    requires_inference_separation: bool = False
    referenced_incident_title: str | None = None
    incident_mismatch: bool = False
    requested_fact_types: list[str] = Field(default_factory=list, max_length=16)
    missing_fact_types: list[str] = Field(default_factory=list, max_length=16)


class KnowledgeDocument(StrictRagModel):
    source_id: str = Field(min_length=3, max_length=512)
    title: str = Field(min_length=1, max_length=512)
    source_kind: Literal["threatlens_doc", "detection_rule", "attack_technique"]
    version: str = Field(min_length=1, max_length=128)
    trust_tier: Literal["governed", "official"]
    text: str = Field(min_length=1)
    source_reference: str = Field(min_length=1, max_length=2048)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeChunk(StrictRagModel):
    chunk_id: str = Field(min_length=16, max_length=64)
    source_id: str
    title: str
    source_kind: str
    version: str
    trust_tier: str
    section: str
    text: str
    source_reference: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievedChunk(StrictRagModel):
    chunk: KnowledgeChunk
    relevance: float = Field(ge=0.0, le=1.0)
    rank: int = Field(ge=1)


class IncidentCitation(StrictRagModel):
    citation_id: str
    source_type: str
    title: str
    snippet: str
    source_reference: str | None = None


class IncidentContext(StrictRagModel):
    incident_uuid: str
    analysis_session_uuid: str
    incident: dict[str, Any]
    citations: list[IncidentCitation]
    prompt_text: str
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


BoundedFinding = Annotated[str, Field(min_length=1, max_length=2000)]
CitationId = Annotated[str, Field(min_length=1, max_length=256)]


class GroundedClaim(StrictRagModel):
    text: BoundedFinding
    citation_ids: list[CitationId] = Field(default_factory=list, max_length=8)


class TechniqueExplanation(StrictRagModel):
    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str | None = Field(default=None, max_length=512)
    observed_evidence: str = Field(min_length=1, max_length=3000)
    evidence_citation_ids: list[CitationId] = Field(default_factory=list, max_length=6)
    governed_explanation: str = Field(min_length=1, max_length=3000)
    knowledge_citation_ids: list[CitationId] = Field(default_factory=list, max_length=6)
    analyst_inference: str | None = Field(default=None, max_length=3000)


class GeneratedInvestigation(StrictRagModel):
    assessment: str = Field(min_length=1, max_length=8000)
    assessment_citation_ids: list[CitationId] = Field(default_factory=list, max_length=12)
    key_findings: list[GroundedClaim] = Field(default_factory=list, max_length=12)
    recommended_actions: list[GroundedClaim] = Field(default_factory=list, max_length=12)
    technique_explanations: list[TechniqueExplanation] = Field(default_factory=list, max_length=12)
    limitations: list[BoundedFinding] = Field(default_factory=list, max_length=12)
    confidence: Literal["low", "medium", "high"] = "medium"


class RagCitation(StrictRagModel):
    citation_id: str
    source_type: str
    title: str
    snippet: str
    source_reference: str | None = None
    relevance: float | None = Field(default=None, ge=0.0, le=1.0)


class RetrievalDiagnostics(StrictRagModel):
    requested_top_k: int
    retrieved_count: int
    accepted_count: int
    minimum_relevance: float
    blocked_injection_chunks: int = 0
    semantic_count: int = 0
    exact_match_count: int = 0
    source_kind_counts: dict[str, int] = Field(default_factory=dict)
    requested_source_ids: list[str] = Field(default_factory=list)
    missing_source_ids: list[str] = Field(default_factory=list)
    retrieval_latency_ms: float = 0.0
    error: str | None = None


class RagQueryResponse(StrictRagModel):
    query_uuid: str
    incident_uuid: str
    status: RagResponseStatus
    assessment: str
    assessment_citation_ids: list[str] = Field(default_factory=list)
    key_findings: list[GroundedClaim] = Field(default_factory=list)
    recommended_actions: list[GroundedClaim] = Field(default_factory=list)
    technique_explanations: list[TechniqueExplanation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    citations: list[RagCitation] = Field(default_factory=list)
    grounding_score: float = Field(ge=0.0, le=1.0)
    unsupported_citation_ids: list[str] = Field(default_factory=list)
    retrieval: RetrievalDiagnostics
    query_plan: RagQueryPlan | None = None
    requested_mode: RagAnalysisMode = RagAnalysisMode.AUTO
    resolved_mode: RagAnalysisMode | None = None
    requested_model: str | None = None
    served_model: str | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None
    routing_reasons: list[str] = Field(default_factory=list)
    routing_score: int = Field(default=0, ge=0)
    generation_latency_ms: float = 0.0
    llm_model: str | None = None
    embedding_model: str | None = None
    knowledge_version: str | None = None
    total_latency_ms: float = 0.0
    created_at: datetime


class RagHealth(StrictRagModel):
    status: Literal["ready", "degraded", "unavailable", "disabled"]
    enabled: bool
    vector_backend: str
    vector_ready: bool
    indexed_chunks: int
    llm_reachable: bool
    llm_model: str
    llm_model_available: bool
    embedding_reachable: bool
    embedding_model: str
    embedding_model_available: bool
    model_profiles: list[RagModelProfileHealth] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)


class RagIndexResult(StrictRagModel):
    status: Literal["indexed", "unchanged", "unavailable"]
    documents_seen: int
    documents_added_or_updated: int
    documents_removed: int
    chunks_upserted: int
    chunks_deleted: int
    indexed_chunks: int
    knowledge_version: str
    manifest_path: str | None = None
    details: list[str] = Field(default_factory=list)


class RagHistoryItem(StrictRagModel):
    query_uuid: str
    actor: str
    question: str
    response_status: str
    grounding_score: float
    citation_count: int
    requested_mode: RagAnalysisMode = RagAnalysisMode.AUTO
    resolved_mode: RagAnalysisMode | None = None
    requested_model: str | None = None
    served_model: str | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None
    routing_score: int = 0
    generation_latency_ms: float = 0.0
    llm_model: str | None
    embedding_model: str | None
    knowledge_version: str | None
    total_latency_ms: float
    created_at: datetime
