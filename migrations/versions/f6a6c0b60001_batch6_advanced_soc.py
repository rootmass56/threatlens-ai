"""Batch 6 advanced SOC capability expansion.

Revision ID: f6a6c0b60001
Revises: e9b5a1300001
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f6a6c0b60001"
down_revision: str | None = "e9b5a1300001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid_columns(name: str) -> list[sa.Column]:
    return [sa.Column("id", sa.Integer(), nullable=False), sa.Column(name, sa.String(length=36), nullable=False)]


def upgrade() -> None:
    op.create_table(
        "ingestion_sources",
        *_uuid_columns("source_uuid"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("connector_id", sa.String(128), nullable=False),
        sa.Column("api_key_hash", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False, server_default="1200"),
        sa.Column("allowed_ip_cidrs_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_uuid"),
        sa.UniqueConstraint("api_key_hash"),
    )
    for col in ("source_uuid", "name", "connector_id", "api_key_hash", "enabled", "created_by", "last_seen_at", "created_at", "updated_at"):
        op.create_index(f"ix_ingestion_sources_{col}", "ingestion_sources", [col], unique=False)
    op.create_index("ix_ingestion_sources_enabled_connector", "ingestion_sources", ["enabled", "connector_id"], unique=False)

    op.create_table(
        "realtime_ingress_events",
        *_uuid_columns("ingress_uuid"),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("client_event_id", sa.String(255), nullable=True),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="accepted"),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("raw_record", sa.Text(), nullable=False),
        sa.Column("analysis_session_uuid", sa.String(36), nullable=True),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["source_id"], ["ingestion_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("ingress_uuid"),
        sa.UniqueConstraint("source_id", "client_event_id", name="uq_realtime_source_client_event"),
    )
    for col in ("ingress_uuid", "source_id", "client_event_id", "payload_sha256", "status", "analysis_session_uuid", "error_code", "received_at", "processed_at"):
        op.create_index(f"ix_realtime_ingress_events_{col}", "realtime_ingress_events", [col], unique=False)
    op.create_index("ix_realtime_ingress_status_received", "realtime_ingress_events", ["status", "received_at"], unique=False)

    op.create_table(
        "threat_intel_feeds",
        *_uuid_columns("feed_uuid"),
        sa.Column("name", sa.String(255), nullable=False), sa.Column("provider", sa.String(255), nullable=False),
        sa.Column("feed_format", sa.String(32), nullable=False), sa.Column("tlp", sa.String(16), nullable=False),
        sa.Column("default_confidence", sa.Integer(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("source_reference", sa.String(2048), nullable=True), sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("last_import_at", sa.DateTime(timezone=True), nullable=True), sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("feed_uuid"), sa.UniqueConstraint("name"),
    )
    for col in ("feed_uuid", "name", "provider", "feed_format", "tlp", "enabled", "last_import_at", "created_by", "created_at", "updated_at"):
        op.create_index(f"ix_threat_intel_feeds_{col}", "threat_intel_feeds", [col], unique=False)

    op.create_table(
        "threat_indicators",
        *_uuid_columns("indicator_uuid"), sa.Column("feed_id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=True), sa.Column("indicator_type", sa.String(64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False), sa.Column("value_normalized", sa.String(2048), nullable=False),
        sa.Column("stix_pattern", sa.Text(), nullable=True), sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("tlp", sa.String(16), nullable=False), sa.Column("malicious_score", sa.Float(), nullable=False),
        sa.Column("tags_json", sa.JSON(), nullable=False), sa.Column("source_reference", sa.String(2048), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True), sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["feed_id"], ["threat_intel_feeds.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("indicator_uuid"),
        sa.UniqueConstraint("feed_id", "indicator_type", "value_normalized", name="uq_feed_indicator_value"),
    )
    for col in ("indicator_uuid", "feed_id", "external_id", "indicator_type", "value_normalized", "confidence", "tlp", "first_seen_at", "last_seen_at", "valid_until", "revoked", "created_at", "updated_at"):
        op.create_index(f"ix_threat_indicators_{col}", "threat_indicators", [col], unique=False)
    op.create_index("ix_threat_indicator_type_value", "threat_indicators", ["indicator_type", "value_normalized"], unique=False)
    op.create_index("ix_threat_indicator_active_window", "threat_indicators", ["revoked", "valid_until"], unique=False)

    op.create_table(
        "threat_intel_hits",
        *_uuid_columns("hit_uuid"), sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True), sa.Column("alert_id", sa.Integer(), nullable=True), sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("matched_field", sa.String(128), nullable=False), sa.Column("matched_value", sa.String(2048), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False), sa.Column("enrichment_only", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["threat_indicators.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("hit_uuid"),
        sa.UniqueConstraint("indicator_id", "event_id", "matched_field", name="uq_intel_hit_event_field"),
    )
    for col in ("hit_uuid", "indicator_id", "event_id", "alert_id", "incident_id", "matched_field", "matched_value", "observed_at", "created_at"):
        op.create_index(f"ix_threat_intel_hits_{col}", "threat_intel_hits", [col], unique=False)
    op.create_index("ix_intel_hits_incident_created", "threat_intel_hits", ["incident_id", "created_at"], unique=False)

    op.create_table(
        "saved_hunts", *_uuid_columns("hunt_uuid"), sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False), sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("query_json", sa.JSON(), nullable=False), sa.Column("shared", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("hunt_uuid"),
    )
    for col in ("hunt_uuid", "name", "owner", "shared", "created_at", "updated_at"):
        op.create_index(f"ix_saved_hunts_{col}", "saved_hunts", [col], unique=False)

    op.create_table(
        "hunt_executions", *_uuid_columns("execution_uuid"), sa.Column("saved_hunt_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False), sa.Column("query_json", sa.JSON(), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False), sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["saved_hunt_id"], ["saved_hunts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("execution_uuid"),
    )
    for col in ("execution_uuid", "saved_hunt_id", "actor", "created_at"):
        op.create_index(f"ix_hunt_executions_{col}", "hunt_executions", [col], unique=False)

    op.create_table(
        "incident_case_profiles", sa.Column("id", sa.Integer(), nullable=False), sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("team", sa.String(255), nullable=True), sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("escalation_level", sa.Integer(), nullable=False), sa.Column("disposition", sa.String(64), nullable=True),
        sa.Column("containment_status", sa.String(64), nullable=False), sa.Column("resolution_reason", sa.Text(), nullable=True),
        sa.Column("watchers_json", sa.JSON(), nullable=False), sa.Column("tags_json", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("incident_id"),
    )
    for col in ("incident_id", "team", "sla_due_at", "escalation_level", "disposition", "containment_status", "updated_by", "created_at", "updated_at"):
        op.create_index(f"ix_incident_case_profiles_{col}", "incident_case_profiles", [col], unique=False)

    op.create_table(
        "incident_tasks", *_uuid_columns("task_uuid"), sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("task_type", sa.String(64), nullable=False), sa.Column("title", sa.String(255), nullable=False), sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("priority", sa.String(16), nullable=False), sa.Column("assignee", sa.String(255), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True), sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False), sa.Column("completed_by", sa.String(255), nullable=True), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("task_uuid"),
    )
    for col in ("task_uuid", "incident_id", "task_type", "status", "priority", "assignee", "due_at", "created_by", "created_at", "updated_at"):
        op.create_index(f"ix_incident_tasks_{col}", "incident_tasks", [col], unique=False)
    op.create_index("ix_incident_tasks_incident_status", "incident_tasks", ["incident_id", "status"], unique=False)

    op.create_table(
        "incident_handoffs", *_uuid_columns("handoff_uuid"), sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("from_actor", sa.String(255), nullable=False), sa.Column("to_actor", sa.String(255), nullable=False),
        sa.Column("note", sa.Text(), nullable=False), sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("handoff_uuid"),
    )
    for col in ("handoff_uuid", "incident_id", "from_actor", "to_actor", "created_at"):
        op.create_index(f"ix_incident_handoffs_{col}", "incident_handoffs", [col], unique=False)

    op.create_table(
        "evidence_custody_events", *_uuid_columns("custody_uuid"), sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False), sa.Column("from_custodian", sa.String(255), nullable=True), sa.Column("to_custodian", sa.String(255), nullable=True),
        sa.Column("location", sa.String(1024), nullable=True), sa.Column("notes", sa.Text(), nullable=False), sa.Column("hash_verified", sa.Boolean(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("custody_uuid"),
    )
    for col in ("custody_uuid", "evidence_id", "action", "actor", "created_at"):
        op.create_index(f"ix_evidence_custody_events_{col}", "evidence_custody_events", [col], unique=False)

    op.create_table(
        "response_playbooks", *_uuid_columns("playbook_uuid"), sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False), sa.Column("action_type", sa.String(128), nullable=False), sa.Column("risk_level", sa.String(32), nullable=False),
        sa.Column("version", sa.String(32), nullable=False), sa.Column("steps_json", sa.JSON(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("playbook_uuid"), sa.UniqueConstraint("name"),
    )
    for col in ("playbook_uuid", "name", "action_type", "risk_level", "enabled", "created_at", "updated_at"):
        op.create_index(f"ix_response_playbooks_{col}", "response_playbooks", [col], unique=False)

    op.create_table(
        "response_executions", *_uuid_columns("execution_uuid"), sa.Column("playbook_id", sa.Integer(), nullable=False), sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("requested_by", sa.String(255), nullable=False), sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True), sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True), sa.Column("executor", sa.String(255), nullable=True),
        sa.Column("parameters_json", sa.JSON(), nullable=False), sa.Column("result_json", sa.JSON(), nullable=False), sa.Column("rollback_notes", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False), sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["playbook_id"], ["response_playbooks.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("execution_uuid"),
    )
    for col in ("execution_uuid", "playbook_id", "incident_id", "status", "requested_by", "approved_by", "executor", "requested_at"):
        op.create_index(f"ix_response_executions_{col}", "response_executions", [col], unique=False)

    op.create_table(
        "detection_feedback", *_uuid_columns("feedback_uuid"), sa.Column("alert_id", sa.Integer(), nullable=True), sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.String(128), nullable=False), sa.Column("actor", sa.String(255), nullable=False), sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False), sa.Column("suppression_scope", sa.String(255), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"), sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("feedback_uuid"),
    )
    for col in ("feedback_uuid", "alert_id", "incident_id", "rule_id", "actor", "verdict", "suppression_scope", "created_at"):
        op.create_index(f"ix_detection_feedback_{col}", "detection_feedback", [col], unique=False)
    op.create_index("ix_detection_feedback_rule_verdict", "detection_feedback", ["rule_id", "verdict"], unique=False)

    op.create_table(
        "detection_tunings", *_uuid_columns("tuning_uuid"), sa.Column("rule_id", sa.String(128), nullable=False), sa.Column("rule_version", sa.String(32), nullable=True),
        sa.Column("proposal_type", sa.String(64), nullable=False), sa.Column("proposal_json", sa.JSON(), nullable=False), sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("requested_by", sa.String(255), nullable=False), sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("patch_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("tuning_uuid"),
    )
    for col in ("tuning_uuid", "rule_id", "proposal_type", "status", "requested_by", "reviewed_by", "created_at", "updated_at"):
        op.create_index(f"ix_detection_tunings_{col}", "detection_tunings", [col], unique=False)


def downgrade() -> None:
    for table in (
        "detection_tunings", "detection_feedback", "response_executions", "response_playbooks",
        "evidence_custody_events", "incident_handoffs", "incident_tasks", "incident_case_profiles",
        "hunt_executions", "saved_hunts", "threat_intel_hits", "threat_indicators", "threat_intel_feeds",
        "realtime_ingress_events", "ingestion_sources",
    ):
        op.drop_table(table)
