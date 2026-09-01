from __future__ import annotations

import argparse
import json

from database.session import session_scope
from rag.runtime import get_rag_runtime


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build or incrementally refresh the governed ThreatLens RAG knowledge index."
    )
    parser.add_argument("--force", action="store_true", help="Rebuild every governed source.")
    args = parser.parse_args()

    runtime = get_rag_runtime()
    with session_scope() as session:
        result = runtime.indexer.index(session, force=args.force)
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    if result.status == "unavailable":
        raise SystemExit(
            "RAG indexing is unavailable. Confirm the local vector store is writable, "
            "Ollama is running, "
            "and the configured embedding model is installed."
        )


if __name__ == "__main__":
    main()
