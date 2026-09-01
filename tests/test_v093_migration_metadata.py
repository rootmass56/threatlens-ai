
from pathlib import Path


def test_v093_migration_adds_semantic_analysis_fingerprint() -> None:
    path = Path("migrations/versions/c31f9a7d4e20_add_analysis_semantic_fingerprint.py")
    text = path.read_text(encoding="utf-8")
    assert 'revision: str = "c31f9a7d4e20"' in text
    assert 'down_revision: str | None = "b9f7d3c2a104"' in text
    assert '"analysis_fingerprint"' in text
    assert '"analysis_context_json"' in text
    assert '"ix_analysis_sessions_analysis_fingerprint"' in text
