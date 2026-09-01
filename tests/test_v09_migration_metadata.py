
from pathlib import Path


def test_v09_migration_has_expected_revision_chain_and_security_tables() -> None:
    path = Path("migrations/versions/b9f7d3c2a104_add_api_authentication_and_rbac.py")
    text = path.read_text(encoding="utf-8")
    assert 'revision: str = "b9f7d3c2a104"' in text
    assert 'down_revision: str | None = "a8c4e2d1f903"' in text
    for table in (
        "security_roles",
        "user_accounts",
        "user_roles",
        "refresh_tokens",
        "login_attempts",
    ):
        assert f'"{table}"' in text
