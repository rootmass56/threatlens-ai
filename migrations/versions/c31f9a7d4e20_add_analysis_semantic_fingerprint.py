
"""Add semantic analysis fingerprint and context persistence.

Revision ID: c31f9a7d4e20
Revises: b9f7d3c2a104
Create Date: 2026-08-09 03:10:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c31f9a7d4e20"
down_revision: str | None = "b9f7d3c2a104"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "analysis_sessions",
        sa.Column("analysis_fingerprint", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "analysis_sessions",
        sa.Column(
            "analysis_context_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.create_index(
        "ix_analysis_sessions_analysis_fingerprint",
        "analysis_sessions",
        ["analysis_fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_analysis_sessions_analysis_fingerprint",
        table_name="analysis_sessions",
    )
    op.drop_column("analysis_sessions", "analysis_context_json")
    op.drop_column("analysis_sessions", "analysis_fingerprint")
