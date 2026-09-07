"""Batch 7 operational performance indexes.

Revision ID: b7f1c2d30001
Revises: f6a6c0b60001
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b7f1c2d30001"
down_revision: str | None = "f6a6c0b60001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Durable AI recovery and operator queue views.
    op.create_index(
        "ix_ai_jobs_recovery_scan",
        "ai_investigation_jobs",
        ["status", "queue_delivery_state", "lease_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_ai_jobs_actor_status_updated",
        "ai_investigation_jobs",
        ["actor", "status", "updated_at"],
        unique=False,
    )

    # High-frequency audit and real-time operations views.
    op.create_index(
        "ix_audit_logs_entity_created",
        "audit_logs",
        ["entity_type", "entity_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_realtime_ingress_source_received",
        "realtime_ingress_events",
        ["source_id", "received_at"],
        unique=False,
    )
    op.create_index(
        "ix_hunt_executions_actor_created",
        "hunt_executions",
        ["actor", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_response_executions_incident_status_requested",
        "response_executions",
        ["incident_id", "status", "requested_at"],
        unique=False,
    )
    op.create_index(
        "ix_incident_tasks_assignee_status_due",
        "incident_tasks",
        ["assignee", "status", "due_at"],
        unique=False,
    )


def downgrade() -> None:
    for index_name, table_name in (
        ("ix_incident_tasks_assignee_status_due", "incident_tasks"),
        ("ix_response_executions_incident_status_requested", "response_executions"),
        ("ix_hunt_executions_actor_created", "hunt_executions"),
        ("ix_realtime_ingress_source_received", "realtime_ingress_events"),
        ("ix_audit_logs_entity_created", "audit_logs"),
        ("ix_ai_jobs_actor_status_updated", "ai_investigation_jobs"),
        ("ix_ai_jobs_recovery_scan", "ai_investigation_jobs"),
    ):
        op.drop_index(index_name, table_name=table_name)
