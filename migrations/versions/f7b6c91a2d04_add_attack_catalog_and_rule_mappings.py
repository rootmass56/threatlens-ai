
"""Add full ATT&CK catalog, relationships, and rule mapping persistence.

Revision ID: f7b6c91a2d04
Revises: e48a7c9d2f10
Create Date: 2026-08-06 01:25:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7b6c91a2d04"
down_revision: str | None = "e48a7c9d2f10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_catalog_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("collection_id", sa.String(length=128), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("source_modified", sa.String(length=64), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("object_count", sa.Integer(), nullable=False),
        sa.Column("active_object_count", sa.Integer(), nullable=False),
        sa.Column("relationship_count", sa.Integer(), nullable=False),
        sa.Column("tactic_count", sa.Integer(), nullable=False),
        sa.Column("technique_count", sa.Integer(), nullable=False),
        sa.Column("subtechnique_count", sa.Integer(), nullable=False),
        sa.Column("object_type_counts_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain",
            "version",
            "content_sha256",
            name="uq_attack_catalog_release_hash",
        ),
    )
    op.create_index(
        op.f("ix_attack_catalog_versions_domain"),
        "attack_catalog_versions",
        ["domain"],
        unique=False,
    )
    op.create_index(
        op.f("ix_attack_catalog_versions_version"),
        "attack_catalog_versions",
        ["version"],
        unique=False,
    )
    op.create_index(
        op.f("ix_attack_catalog_versions_content_sha256"),
        "attack_catalog_versions",
        ["content_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_attack_catalog_versions_is_active"),
        "attack_catalog_versions",
        ["is_active"],
        unique=False,
    )

    op.create_table(
        "attack_objects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("catalog_version_id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(length=128), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=False),
        sa.Column("attack_id", sa.String(length=32), nullable=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created", sa.String(length=64), nullable=True),
        sa.Column("modified", sa.String(length=64), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("parent_attack_id", sa.String(length=32), nullable=True),
        sa.Column("tactic_shortnames_json", sa.JSON(), nullable=False),
        sa.Column("platforms_json", sa.JSON(), nullable=False),
        sa.Column("external_url", sa.Text(), nullable=True),
        sa.Column("shortname", sa.String(length=128), nullable=True),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["catalog_version_id"],
            ["attack_catalog_versions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "catalog_version_id",
            "stix_id",
            name="uq_attack_object_catalog_stix",
        ),
    )
    for column in (
        "catalog_version_id",
        "stix_id",
        "object_type",
        "attack_id",
        "modified",
        "revoked",
        "deprecated",
        "active",
        "is_subtechnique",
        "parent_attack_id",
        "shortname",
    ):
        op.create_index(
            op.f(f"ix_attack_objects_{column}"),
            "attack_objects",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_attack_objects_catalog_type_active",
        "attack_objects",
        ["catalog_version_id", "object_type", "active"],
        unique=False,
    )
    op.create_index(
        "ix_attack_objects_catalog_attack_id",
        "attack_objects",
        ["catalog_version_id", "attack_id"],
        unique=False,
    )

    op.create_table(
        "attack_relationships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("catalog_version_id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(length=128), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("source_ref", sa.String(length=128), nullable=False),
        sa.Column("target_ref", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created", sa.String(length=64), nullable=True),
        sa.Column("modified", sa.String(length=64), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["catalog_version_id"],
            ["attack_catalog_versions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "catalog_version_id",
            "stix_id",
            name="uq_attack_relationship_catalog_stix",
        ),
    )
    for column in (
        "catalog_version_id",
        "stix_id",
        "relationship_type",
        "source_ref",
        "target_ref",
        "revoked",
    ):
        op.create_index(
            op.f(f"ix_attack_relationships_{column}"),
            "attack_relationships",
            [column],
            unique=False,
        )

    op.create_table(
        "rule_attack_mappings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("catalog_version_id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("detection_name", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("rule_status", sa.String(length=32), nullable=False),
        sa.Column("dataset", sa.String(length=128), nullable=True),
        sa.Column("attack_id", sa.String(length=32), nullable=False),
        sa.Column("catalog_stix_id", sa.String(length=128), nullable=True),
        sa.Column("catalog_name", sa.String(length=512), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("declared_tactic", sa.String(length=128), nullable=False),
        sa.Column("catalog_tactics_json", sa.JSON(), nullable=False),
        sa.Column("valid_catalog_id", sa.Boolean(), nullable=False),
        sa.Column("active_catalog_object", sa.Boolean(), nullable=False),
        sa.Column("tactic_consistent", sa.Boolean(), nullable=False),
        sa.Column("valid", sa.Boolean(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["catalog_version_id"],
            ["attack_catalog_versions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "catalog_version_id",
            "rule_id",
            "rule_version",
            "attack_id",
            "role",
            name="uq_rule_attack_mapping_version",
        ),
    )
    for column in (
        "catalog_version_id",
        "rule_id",
        "detection_name",
        "rule_status",
        "dataset",
        "attack_id",
        "catalog_stix_id",
        "valid_catalog_id",
        "active_catalog_object",
        "tactic_consistent",
        "valid",
    ):
        op.create_index(
            op.f(f"ix_rule_attack_mappings_{column}"),
            "rule_attack_mappings",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_rule_attack_mappings_catalog_valid",
        "rule_attack_mappings",
        ["catalog_version_id", "valid"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_rule_attack_mappings_catalog_valid",
        table_name="rule_attack_mappings",
    )
    op.drop_table("rule_attack_mappings")
    op.drop_table("attack_relationships")
    op.drop_index("ix_attack_objects_catalog_attack_id", table_name="attack_objects")
    op.drop_index("ix_attack_objects_catalog_type_active", table_name="attack_objects")
    op.drop_table("attack_objects")
    op.drop_table("attack_catalog_versions")
