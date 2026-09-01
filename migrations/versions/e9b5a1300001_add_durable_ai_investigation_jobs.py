
"""Add durable asynchronous AI investigation jobs.

Revision ID: e9b5a1300001
Revises: d4a7c0e51010
Create Date: 2026-08-30 09:10:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e9b5a1300001"
down_revision: str | None = "d4a7c0e51010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_investigation_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_uuid", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("question_sha256", sa.String(length=64), nullable=False),
        sa.Column("analysis_mode", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=True),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("worker_id", sa.String(length=255), nullable=True),
        sa.Column("queue_delivery_state", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("result_query_uuid", sa.String(length=36), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key_hash", name="uq_ai_job_idempotency_key_hash"),
        sa.UniqueConstraint("job_uuid"),
    )
    for name, columns, unique in (
        ("ix_ai_investigation_jobs_job_uuid", ["job_uuid"], True),
        ("ix_ai_investigation_jobs_incident_id", ["incident_id"], False),
        ("ix_ai_investigation_jobs_actor", ["actor"], False),
        ("ix_ai_investigation_jobs_question_sha256", ["question_sha256"], False),
        ("ix_ai_investigation_jobs_analysis_mode", ["analysis_mode"], False),
        ("ix_ai_investigation_jobs_status", ["status"], False),
        ("ix_ai_investigation_jobs_idempotency_key_hash", ["idempotency_key_hash"], False),
        ("ix_ai_investigation_jobs_request_fingerprint", ["request_fingerprint"], False),
        ("ix_ai_investigation_jobs_worker_id", ["worker_id"], False),
        ("ix_ai_investigation_jobs_queue_delivery_state", ["queue_delivery_state"], False),
        ("ix_ai_investigation_jobs_result_query_uuid", ["result_query_uuid"], False),
        ("ix_ai_investigation_jobs_error_code", ["error_code"], False),
        ("ix_ai_investigation_jobs_lease_expires_at", ["lease_expires_at"], False),
        ("ix_ai_investigation_jobs_created_at", ["created_at"], False),
        ("ix_ai_investigation_jobs_updated_at", ["updated_at"], False),
        ("ix_ai_jobs_status_created", ["status", "created_at"], False),
        ("ix_ai_jobs_incident_status", ["incident_id", "status"], False),
    ):
        op.create_index(name, "ai_investigation_jobs", columns, unique=unique)


def downgrade() -> None:
    for name in (
        "ix_ai_jobs_incident_status",
        "ix_ai_jobs_status_created",
        "ix_ai_investigation_jobs_updated_at",
        "ix_ai_investigation_jobs_created_at",
        "ix_ai_investigation_jobs_lease_expires_at",
        "ix_ai_investigation_jobs_error_code",
        "ix_ai_investigation_jobs_result_query_uuid",
        "ix_ai_investigation_jobs_queue_delivery_state",
        "ix_ai_investigation_jobs_worker_id",
        "ix_ai_investigation_jobs_request_fingerprint",
        "ix_ai_investigation_jobs_idempotency_key_hash",
        "ix_ai_investigation_jobs_status",
        "ix_ai_investigation_jobs_analysis_mode",
        "ix_ai_investigation_jobs_question_sha256",
        "ix_ai_investigation_jobs_actor",
        "ix_ai_investigation_jobs_incident_id",
        "ix_ai_investigation_jobs_job_uuid",
    ):
        op.drop_index(name, table_name="ai_investigation_jobs")
    op.drop_table("ai_investigation_jobs")
