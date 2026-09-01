
"""add common schema and external rule metadata

Revision ID: e48a7c9d2f10
Revises: cd04d71fd7d2
Create Date: 2026-07-30 17:30:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "e48a7c9d2f10"
down_revision: str | Sequence[str] | None = "cd04d71fd7d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("analysis_sessions") as batch_op:
        batch_op.add_column(sa.Column("connector_id", sa.String(length=128), nullable=True))
        batch_op.add_column(
            sa.Column(
                "schema_version",
                sa.String(length=32),
                nullable=False,
                server_default="1.0.0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "rule_catalog_version",
                sa.String(length=32),
                nullable=False,
                server_default="0.4.0",
            )
        )
        batch_op.add_column(
            sa.Column("total_quarantined", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("parse_success_rate", sa.Float(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("parser_statistics_json", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.create_index("ix_analysis_sessions_connector_id", ["connector_id"])

    with op.batch_alter_table("events") as batch_op:
        batch_op.add_column(
            sa.Column(
                "schema_version",
                sa.String(length=32),
                nullable=False,
                server_default="1.0.0",
            )
        )
        batch_op.add_column(sa.Column("original_timestamp", sa.String(length=256)))
        batch_op.add_column(sa.Column("timezone", sa.String(length=64)))
        batch_op.add_column(sa.Column("source_category", sa.String(length=64)))
        batch_op.add_column(sa.Column("source_product", sa.String(length=64)))
        batch_op.add_column(sa.Column("source_service", sa.String(length=64)))
        batch_op.add_column(sa.Column("source_dataset", sa.String(length=128)))
        batch_op.add_column(sa.Column("process_id", sa.Integer()))
        batch_op.add_column(sa.Column("parent_process_name", sa.String(length=512)))
        batch_op.add_column(sa.Column("command_line", sa.Text()))
        batch_op.add_column(sa.Column("source_port", sa.Integer()))
        batch_op.add_column(sa.Column("destination_port", sa.Integer()))
        batch_op.add_column(sa.Column("file_path", sa.Text()))
        batch_op.add_column(sa.Column("domain", sa.String(length=1024)))
        batch_op.add_column(sa.Column("url", sa.Text()))
        batch_op.add_column(sa.Column("parser_name", sa.String(length=128)))
        batch_op.add_column(sa.Column("parser_version", sa.String(length=32)))
        batch_op.add_column(
            sa.Column(
                "parse_status",
                sa.String(length=32),
                nullable=False,
                server_default="parsed",
            )
        )
        batch_op.add_column(
            sa.Column("data_quality_json", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.create_index("ix_events_source_category", ["source_category"])
        batch_op.create_index("ix_events_source_product", ["source_product"])
        batch_op.create_index("ix_events_source_service", ["source_service"])
        batch_op.create_index("ix_events_source_dataset", ["source_dataset"])

    with op.batch_alter_table("alerts") as batch_op:
        batch_op.add_column(sa.Column("rule_id", sa.String(length=36)))
        batch_op.add_column(sa.Column("rule_title", sa.String(length=255)))
        batch_op.add_column(sa.Column("rule_status", sa.String(length=32)))
        batch_op.add_column(sa.Column("playbook", sa.String(length=255)))
        batch_op.add_column(
            sa.Column("risk_factors_json", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.add_column(sa.Column("risk_policy_version", sa.String(length=32)))
        batch_op.create_index("ix_alerts_rule_id", ["rule_id"])


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_index("ix_alerts_rule_id")
        batch_op.drop_column("risk_policy_version")
        batch_op.drop_column("risk_factors_json")
        batch_op.drop_column("playbook")
        batch_op.drop_column("rule_status")
        batch_op.drop_column("rule_title")
        batch_op.drop_column("rule_id")

    with op.batch_alter_table("events") as batch_op:
        batch_op.drop_index("ix_events_source_dataset")
        batch_op.drop_index("ix_events_source_service")
        batch_op.drop_index("ix_events_source_product")
        batch_op.drop_index("ix_events_source_category")
        batch_op.drop_column("data_quality_json")
        batch_op.drop_column("parse_status")
        batch_op.drop_column("parser_version")
        batch_op.drop_column("parser_name")
        batch_op.drop_column("url")
        batch_op.drop_column("domain")
        batch_op.drop_column("file_path")
        batch_op.drop_column("destination_port")
        batch_op.drop_column("source_port")
        batch_op.drop_column("command_line")
        batch_op.drop_column("parent_process_name")
        batch_op.drop_column("process_id")
        batch_op.drop_column("source_dataset")
        batch_op.drop_column("source_service")
        batch_op.drop_column("source_product")
        batch_op.drop_column("source_category")
        batch_op.drop_column("timezone")
        batch_op.drop_column("original_timestamp")
        batch_op.drop_column("schema_version")

    with op.batch_alter_table("analysis_sessions") as batch_op:
        batch_op.drop_index("ix_analysis_sessions_connector_id")
        batch_op.drop_column("parser_statistics_json")
        batch_op.drop_column("parse_success_rate")
        batch_op.drop_column("total_quarantined")
        batch_op.drop_column("rule_catalog_version")
        batch_op.drop_column("schema_version")
        batch_op.drop_column("connector_id")
