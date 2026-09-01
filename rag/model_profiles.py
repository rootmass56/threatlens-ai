from __future__ import annotations

from dataclasses import dataclass

from rag.config import RagSettings
from rag.models import RagAnalysisMode


@dataclass(frozen=True)
class RagModelProfile:
    mode: RagAnalysisMode
    name: str
    model_name: str
    num_ctx: int
    num_predict: int
    read_timeout_seconds: int


def build_model_profiles(settings: RagSettings) -> dict[RagAnalysisMode, RagModelProfile]:
    """Build the two governed local-model profiles used by the adaptive runtime."""

    return {
        RagAnalysisMode.STANDARD: RagModelProfile(
            mode=RagAnalysisMode.STANDARD,
            name="Standard",
            model_name=settings.llm_model,
            num_ctx=settings.ollama_num_ctx,
            num_predict=settings.ollama_num_predict,
            read_timeout_seconds=settings.read_timeout_seconds,
        ),
        RagAnalysisMode.DEEP: RagModelProfile(
            mode=RagAnalysisMode.DEEP,
            name="Deep Analysis",
            model_name=settings.deep_llm_model,
            num_ctx=settings.deep_ollama_num_ctx,
            num_predict=settings.deep_ollama_num_predict,
            read_timeout_seconds=settings.deep_read_timeout_seconds,
        ),
    }
