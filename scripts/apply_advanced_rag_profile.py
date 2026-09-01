from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

PROFILE = {
    "THREATLENS_RAG_VECTOR_BACKEND": "sqlite",
    "THREATLENS_RAG_VECTOR_PATH": "data/rag/vector_store.sqlite3",
    "THREATLENS_RAG_COLLECTION": "threatlens-v0111-knowledge",
    "THREATLENS_RAG_TOP_K": "3",
    "THREATLENS_RAG_MAX_INCIDENT_CONTEXT_CHARS": "6500",
    "THREATLENS_RAG_MAX_KNOWLEDGE_CONTEXT_CHARS": "6000",
    "THREATLENS_RAG_STANDARD_LLM_MODEL": "qwen3:4b",
    "THREATLENS_RAG_DEEP_LLM_MODEL": "qwen3:8b",
    "THREATLENS_RAG_READ_TIMEOUT_SECONDS": "360",
    "THREATLENS_RAG_API_TIMEOUT_SECONDS": "1320",
    "THREATLENS_RAG_OLLAMA_NUM_CTX": "4096",
    "THREATLENS_RAG_OLLAMA_NUM_PREDICT": "900",
    "THREATLENS_RAG_DEEP_READ_TIMEOUT_SECONDS": "600",
    "THREATLENS_RAG_DEEP_OLLAMA_NUM_CTX": "8192",
    "THREATLENS_RAG_DEEP_OLLAMA_NUM_PREDICT": "1400",
    "THREATLENS_RAG_AUTO_DEEP_THRESHOLD": "5",
    "THREATLENS_RAG_FALLBACK_TO_STANDARD": "1",
    "THREATLENS_RAG_EXACT_KNOWLEDGE_LIMIT": "8",
}


def _update_lines(lines: list[str]) -> list[str]:
    remaining = dict(PROFILE)
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if "=" not in stripped or stripped.startswith("#"):
            output.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            output.append(f"{key}={remaining.pop(key)}")
        else:
            output.append(line)
    if remaining:
        if output and output[-1].strip():
            output.append("")
        output.append("# ThreatLens advanced grounded-RAG profile")
        output.extend(f"{key}={value}" for key, value in remaining.items())
    return output


def main() -> None:
    if ENV_PATH.is_file():
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = ENV_PATH.with_name(f".env.before_advanced_rag_{timestamp}.bak")
        backup.write_bytes(ENV_PATH.read_bytes())
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
        print(f"Backed up existing .env to {backup.name}")
    else:
        example = ROOT / ".env.example"
        lines = example.read_text(encoding="utf-8").splitlines() if example.is_file() else []
        print("No .env existed; creating one from the available example/settings.")

    ENV_PATH.write_text("\n".join(_update_lines(lines)).rstrip() + "\n", encoding="utf-8")
    print("Applied ThreatLens v0.11.1 security-closed grounded-RAG runtime profile.")
    for key, value in PROFILE.items():
        print(f"  {key}={value}")
    print("Existing secrets and unrelated environment settings were preserved.")


if __name__ == "__main__":
    main()
