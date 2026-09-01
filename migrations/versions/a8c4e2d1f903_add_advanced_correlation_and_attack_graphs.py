
"""Add advanced correlation, entity resolution and attack graph persistence.

Revision ID: a8c4e2d1f903
Revises: f7b6c91a2d04
Create Date: 2026-08-06 22:45:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8c4e2d1f903"
down_revision: str | None = "f7b6c91a2d04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(sa.Column("correlation_id", sa.String(length=36), nullable=True))
        batch_op.add_column(
            sa.Column("correlation_version", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("representative_alert_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("deduplicated_alert_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("source_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("entity_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("relationship_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("stage_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("stage_progression", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("graph_score", sa.Float(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("storyline", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("correlation_metadata_json", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.create_index("ix_incidents_correlation_id", ["correlation_id"], unique=False)

    op.create_table(
        "correlation_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("correlation_uuid", sa.String(length=36), nullable=False),
        sa.Column("analysis_session_id", sa.Integer(), nullable=False),
        sa.Column("algorithm_version", sa.String(length=32), nullable=False),
        sa.Column("policy_json", sa.JSON(), nullable=False),
        sa.Column("input_alerts", sa.Integer(), nullable=False),
        sa.Column("representative_alerts", sa.Integer(), nullable=False),
        sa.Column("deduplicated_alerts", sa.Integer(), nullable=False),
        sa.Column("duplicate_groups", sa.Integer(), nullable=False),
        sa.Column("entity_count", sa.Integer(), nullable=False),
        sa.Column("relationship_count", sa.Integer(), nullable=False),
        sa.Column("incident_count", sa.Integer(), nullable=False),
        sa.Column("graph_node_count", sa.Integer(), nullable=False),
        sa.Column("graph_edge_count", sa.Integer(), nullable=False),
        sa.Column("metrics_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_session_id"], ["analysis_sessions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_uuid"),
        sa.UniqueConstraint(
            "analysis_session_id",
            "algorithm_version",
            name="uq_correlation_run_session_version",
        ),
    )
    for column in ("correlation_uuid", "analysis_session_id", "algorithm_version"):
        op.create_index(
            op.f(f"ix_correlation_runs_{column}"),
            "correlation_runs",
            [column],
            unique=(column == "correlation_uuid"),
        )

    op.create_table(
        "correlation_entities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("entity_uuid", sa.String(length=36), nullable=False),
        sa.Column("correlation_run_id", sa.Integer(), nullable=False),
        sa.Column("entity_key", sa.String(length=1024), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("canonical_value", sa.Text(), nullable=False),
        sa.Column("display_value", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("aliases_json", sa.JSON(), nullable=False),
        sa.Column("source_datasets_json", sa.JSON(), nullable=False),
        sa.Column("evidence_alert_ids_json", sa.JSON(), nullable=False),
        sa.Column("evidence_event_ids_json", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_run_id"], ["correlation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_uuid"),
        sa.UniqueConstraint(
            "correlation_run_id",
            "entity_key",
            name="uq_correlation_entity_run_key",
        ),
    )
    for column in (
        "entity_uuid",
        "correlation_run_id",
        "entity_key",
        "entity_type",
        "first_seen",
        "last_seen",
    ):
        op.create_index(
            op.f(f"ix_correlation_entities_{column}"),
            "correlation_entities",
            [column],
            unique=(column == "entity_uuid"),
        )
    op.create_index(
        "ix_correlation_entities_run_type",
        "correlation_entities",
        ["correlation_run_id", "entity_type"],
        unique=False,
    )

    op.create_table(
        "incident_entities",
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["entity_id"], ["correlation_entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "entity_id"),
    )

    op.create_table(
        "correlation_relationships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("relationship_uuid", sa.String(length=36), nullable=False),
        sa.Column("correlation_run_id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("source_node_key", sa.String(length=1024), nullable=False),
        sa.Column("target_node_key", sa.String(length=1024), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("shared_entity_count", sa.Integer(), nullable=False),
        sa.Column("cluster_eligible", sa.Boolean(), nullable=False),
        sa.Column("reasons_json", sa.JSON(), nullable=False),
        sa.Column("shared_entities_json", sa.JSON(), nullable=False),
        sa.Column("evidence_alert_ids_json", sa.JSON(), nullable=False),
        sa.Column("time_delta_seconds", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_run_id"], ["correlation_runs.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("relationship_uuid"),
    )
    for column in (
        "relationship_uuid",
        "correlation_run_id",
        "incident_id",
        "source_node_key",
        "target_node_key",
        "relationship_type",
        "confidence",
        "cluster_eligible",
    ):
        op.create_index(
            op.f(f"ix_correlation_relationships_{column}"),
            "correlation_relationships",
            [column],
            unique=(column == "relationship_uuid"),
        )
    op.create_index(
        "ix_correlation_relationships_run_confidence",
        "correlation_relationships",
        ["correlation_run_id", "confidence"],
        unique=False,
    )

    op.create_table(
        "attack_graph_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("graph_uuid", sa.String(length=36), nullable=False),
        sa.Column("correlation_run_id", sa.Integer(), nullable=False),
        sa.Column("graph_schema", sa.String(length=64), nullable=False),
        sa.Column("graph_sha256", sa.String(length=64), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("edge_count", sa.Integer(), nullable=False),
        sa.Column("graph_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_run_id"], ["correlation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("graph_uuid"),
        sa.UniqueConstraint("correlation_run_id"),
    )
    for column in ("graph_uuid", "correlation_run_id", "graph_sha256"):
        op.create_index(
            op.f(f"ix_attack_graph_snapshots_{column}"),
            "attack_graph_snapshots",
            [column],
            unique=(column in {"graph_uuid", "correlation_run_id"}),
        )


def downgrade() -> None:
    op.drop_table("attack_graph_snapshots")
    op.drop_index(
        "ix_correlation_relationships_run_confidence",
        table_name="correlation_relationships",
    )
    op.drop_table("correlation_relationships")
    op.drop_table("incident_entities")
    op.drop_index("ix_correlation_entities_run_type", table_name="correlation_entities")
    op.drop_table("correlation_entities")
    op.drop_table("correlation_runs")

    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_index("ix_incidents_correlation_id")
        for column in (
            "correlation_metadata_json",
            "storyline",
            "graph_score",
            "stage_progression",
            "stage_count",
            "relationship_count",
            "entity_count",
            "source_count",
            "deduplicated_alert_count",
            "representative_alert_count",
            "correlation_version",
            "correlation_id",
        ):
            batch_op.drop_column(column)
