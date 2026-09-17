from __future__ import annotations

from fastapi.params import Depends as DependsParam

from api.dependencies import DatabaseSession


def test_database_session_commits_before_response_is_sent() -> None:
    """The transactional dependency must finish before the HTTP response leaves FastAPI."""
    metadata = list(getattr(DatabaseSession, "__metadata__", ()))
    dependencies = [item for item in metadata if isinstance(item, DependsParam)]
    assert len(dependencies) == 1
    assert dependencies[0].scope == "function"