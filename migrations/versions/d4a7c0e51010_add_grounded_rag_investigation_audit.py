
"""Add grounded RAG investigation query audit persistence.

Revision ID: d4a7c0e51010
Revises: c31f9a7d4e20
Create Date: 2026-08-11 16:10:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4a7c0e51010"
down_revision: str | None = "c31f9a7d4e20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rag_investigation_queries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("query_uuid", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("question_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_status", sa.String(length=64), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=False),
        sa.Column("citation_ids_json", sa.JSON(), nullable=False),
        sa.Column("grounding_score", sa.Float(), nullable=False),
        sa.Column("retrieval_count", sa.Integer(), nullable=False),
        sa.Column("llm_model", sa.String(length=255), nullable=True),
        sa.Column("embedding_model", sa.String(length=255), nullable=True),
        sa.Column("knowledge_version", sa.String(length=128), nullable=True),
        sa.Column("total_latency_ms", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("query_uuid"),
    )
    op.create_index("ix_rag_investigation_queries_query_uuid", "rag_investigation_queries", ["query_uuid"], unique=True)
    op.create_index("ix_rag_investigation_queries_incident_id", "rag_investigation_queries", ["incident_id"], unique=False)
    op.create_index("ix_rag_investigation_queries_actor", "rag_investigation_queries", ["actor"], unique=False)
    op.create_index("ix_rag_investigation_queries_question_sha256", "rag_investigation_queries", ["question_sha256"], unique=False)
    op.create_index("ix_rag_investigation_queries_response_status", "rag_investigation_queries", ["response_status"], unique=False)
    op.create_index("ix_rag_investigation_queries_knowledge_version", "rag_investigation_queries", ["knowledge_version"], unique=False)
    op.create_index("ix_rag_investigation_queries_created_at", "rag_investigation_queries", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_rag_investigation_queries_created_at", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_knowledge_version", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_response_status", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_question_sha256", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_actor", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_incident_id", table_name="rag_investigation_queries")
    op.drop_index("ix_rag_investigation_queries_query_uuid", table_name="rag_investigation_queries")
    op.drop_table("rag_investigation_queries")
