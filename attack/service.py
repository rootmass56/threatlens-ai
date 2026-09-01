from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from attack.catalog import AttackCatalog
from attack.coverage import AttackCoverageReport, build_attack_coverage_report
from attack.mapping import RuleAttackMappingRecord
from attack.navigator import build_navigator_layer
from attack.sources import (
    ALL_ATTACK_SOURCES,
    ENTERPRISE_ATTACK_SOURCE,
    AttackCatalogSource,
    ensure_attack_bundle,
)
from core.rules.loader import DEFAULT_RULE_DIRECTORY, RuleLoader
from core.rules.models import ThreatLensRule
from database.models import (
    AttackCatalogVersionModel,
    AttackObjectModel,
    AttackRelationshipModel,
    AuditLogModel,
    RuleAttackMappingModel,
    utc_now,
)
from database.session import session_scope

SessionContextFactory = Callable[[], AbstractContextManager[Session]]
_ATTACK_SYNCHRONIZATION_LOCK = RLock()


@dataclass(frozen=True, slots=True)
class AttackSyncResult:
    catalog_id: int
    domain: str
    version: str
    content_sha256: str
    object_count: int
    relationship_count: int
    tactic_count: int
    technique_count: int
    subtechnique_count: int
    rule_count: int
    mapping_count: int
    valid_mapping_count: int
    invalid_mapping_count: int
    unique_mapped_attack_ids: int
    rule_coverage_percent: float
    reused_catalog: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackCatalogService:
    """Synchronize and query a complete, pinned official ATT&CK catalog."""

    def __init__(
        self,
        session_context_factory: SessionContextFactory = session_scope,
        rule_directory: Path = DEFAULT_RULE_DIRECTORY,
    ) -> None:
        self._session_context_factory = session_context_factory
        self._rule_directory = rule_directory

    def _load_catalog(
        self,
        *,
        source: AttackCatalogSource = ENTERPRISE_ATTACK_SOURCE,
        allow_network: bool,
        force_download: bool,
        bundle_path: Path | None = None,
    ) -> AttackCatalog:
        bundle_path = bundle_path or ensure_attack_bundle(
            source,
            allow_network=allow_network,
            force=force_download,
        )
        catalog = AttackCatalog.from_path(bundle_path, source)
        catalog.validate_expected_counts()
        return catalog

    def synchronize(
        self,
        *,
        source: AttackCatalogSource = ENTERPRISE_ATTACK_SOURCE,
        allow_network: bool = True,
        force_download: bool = False,
        actor: str = "system",
        bundle_path: Path | None = None,
        rules: Iterable[ThreatLensRule] | None = None,
    ) -> AttackSyncResult:
        """Persist every STIX object, relationship and validated rule mapping atomically."""

        # Catalogue replacement combines an atomic file swap with check-then-write database
        # state. Serialize the operation in the current single-process profile so two API/CLI
        # synchronizations cannot race the unique catalogue release or active-version state.
        with _ATTACK_SYNCHRONIZATION_LOCK:
            return self._synchronize_locked(
                source=source,
                allow_network=allow_network,
                force_download=force_download,
                actor=actor,
                bundle_path=bundle_path,
                rules=rules,
            )

    def _synchronize_locked(
        self,
        *,
        source: AttackCatalogSource,
        allow_network: bool,
        force_download: bool,
        actor: str,
        bundle_path: Path | None,
        rules: Iterable[ThreatLensRule] | None,
    ) -> AttackSyncResult:
        catalog = self._load_catalog(
            source=source,
            allow_network=allow_network,
            force_download=force_download,
            bundle_path=bundle_path,
        )
        selected_rules = tuple(
            rules
            if rules is not None
            else RuleLoader(self._rule_directory).load(enabled_only=False)
        )
        coverage = build_attack_coverage_report(catalog, selected_rules)
        summary = catalog.summary()

        with self._session_context_factory() as database_session:
            existing = database_session.scalars(
                select(AttackCatalogVersionModel).where(
                    AttackCatalogVersionModel.domain == source.domain,
                    AttackCatalogVersionModel.version == source.version,
                    AttackCatalogVersionModel.content_sha256 == catalog.content_sha256,
                )
            ).first()

            database_session.execute(
                update(AttackCatalogVersionModel)
                .where(AttackCatalogVersionModel.domain == source.domain)
                .values(is_active=False)
            )

            reused_catalog = existing is not None
            if existing is None:
                catalog_model = AttackCatalogVersionModel(
                    domain=source.domain,
                    display_name=source.display_name,
                    version=source.version,
                    collection_id=source.collection_id,
                    source_url=source.source_url,
                    source_modified=source.modified,
                    content_sha256=catalog.content_sha256,
                    object_count=summary.object_count,
                    active_object_count=summary.active_object_count,
                    relationship_count=summary.relationship_count,
                    tactic_count=summary.tactic_count,
                    technique_count=summary.technique_count,
                    subtechnique_count=summary.subtechnique_count,
                    object_type_counts_json=summary.object_types,
                    metadata_json={
                        "bundle_path": str(catalog.bundle_path),
                        "catalog_awareness_percent": 100.0,
                        "mitigation_count": summary.mitigation_count,
                        "group_count": summary.group_count,
                        "software_count": summary.software_count,
                        "campaign_count": summary.campaign_count,
                        "detection_strategy_count": summary.detection_strategy_count,
                        "analytic_count": summary.analytic_count,
                        "data_component_count": summary.data_component_count,
                    },
                    is_active=True,
                )
                database_session.add(catalog_model)
                database_session.flush()
                catalog_id = catalog_model.id

                object_rows = [
                    {
                        "catalog_version_id": catalog_id,
                        "stix_id": item.stix_id,
                        "object_type": item.object_type,
                        "attack_id": item.attack_id,
                        "name": item.name,
                        "description": item.description,
                        "created": item.created,
                        "modified": item.modified,
                        "revoked": item.revoked,
                        "deprecated": item.deprecated,
                        "active": item.active,
                        "is_subtechnique": item.is_subtechnique,
                        "parent_attack_id": item.parent_attack_id,
                        "tactic_shortnames_json": list(item.tactic_shortnames),
                        "platforms_json": list(item.platforms),
                        "external_url": item.external_url,
                        "shortname": item.shortname,
                        "raw_json": item.raw,
                    }
                    for item in catalog.objects
                ]
                relationship_rows = [
                    {
                        "catalog_version_id": catalog_id,
                        "stix_id": item.stix_id,
                        "relationship_type": item.relationship_type,
                        "source_ref": item.source_ref,
                        "target_ref": item.target_ref,
                        "description": item.description,
                        "created": item.created,
                        "modified": item.modified,
                        "revoked": item.revoked,
                        "raw_json": item.raw,
                    }
                    for item in catalog.relationships
                ]
                database_session.bulk_insert_mappings(AttackObjectModel, object_rows)
                database_session.bulk_insert_mappings(
                    AttackRelationshipModel,
                    relationship_rows,
                )
            else:
                catalog_id = existing.id
                existing.is_active = True
                existing.synced_at = utc_now()
                existing.metadata_json = {
                    **(existing.metadata_json or {}),
                    "bundle_path": str(catalog.bundle_path),
                    "catalog_awareness_percent": 100.0,
                }

            database_session.execute(
                delete(RuleAttackMappingModel).where(
                    RuleAttackMappingModel.catalog_version_id == catalog_id
                )
            )
            mapping_rows = [self._mapping_row(catalog_id, item) for item in coverage.mappings]
            database_session.bulk_insert_mappings(RuleAttackMappingModel, mapping_rows)

            database_session.add(
                AuditLogModel(
                    actor=actor,
                    action="attack.catalog_synchronized",
                    entity_type="attack_catalog",
                    entity_id=f"{source.domain}:{source.version}",
                    details_json={
                        **asdict(summary),
                        "catalog_id": catalog_id,
                        "collection_id": source.collection_id,
                        "source_url": source.source_url,
                        "mapping_count": coverage.mapping_count,
                        "valid_mapping_count": coverage.valid_mapping_count,
                        "invalid_mapping_count": coverage.invalid_mapping_count,
                        "unique_mapped_attack_ids": coverage.unique_mapped_attack_ids,
                        "rule_coverage_percent": coverage.rule_coverage_percent,
                        "reused_catalog": reused_catalog,
                    },
                )
            )

        return AttackSyncResult(
            catalog_id=catalog_id,
            domain=source.domain,
            version=source.version,
            content_sha256=catalog.content_sha256,
            object_count=summary.object_count,
            relationship_count=summary.relationship_count,
            tactic_count=summary.tactic_count,
            technique_count=summary.technique_count,
            subtechnique_count=summary.subtechnique_count,
            rule_count=len(selected_rules),
            mapping_count=coverage.mapping_count,
            valid_mapping_count=coverage.valid_mapping_count,
            invalid_mapping_count=coverage.invalid_mapping_count,
            unique_mapped_attack_ids=coverage.unique_mapped_attack_ids,
            rule_coverage_percent=coverage.rule_coverage_percent,
            reused_catalog=reused_catalog,
        )

    def synchronize_all(
        self,
        *,
        allow_network: bool = True,
        force_download: bool = False,
        actor: str = "system",
    ) -> tuple[AttackSyncResult, ...]:
        """Synchronize every official ATT&CK v19.1 domain supported by MITRE."""

        with _ATTACK_SYNCHRONIZATION_LOCK:
            enterprise_rules = RuleLoader(self._rule_directory).load(enabled_only=False)
            results: list[AttackSyncResult] = []
            for source in ALL_ATTACK_SOURCES:
                results.append(
                    self.synchronize(
                        source=source,
                        allow_network=allow_network,
                        force_download=force_download,
                        actor=actor,
                        rules=(enterprise_rules if source.domain == "enterprise-attack" else ()),
                    )
                )
            return tuple(results)

    @staticmethod
    def _mapping_row(
        catalog_id: int,
        item: RuleAttackMappingRecord,
    ) -> dict[str, Any]:
        return {
            "catalog_version_id": catalog_id,
            "rule_id": item.rule_id,
            "detection_name": item.detection_name,
            "rule_version": item.rule_version,
            "rule_status": item.rule_status,
            "dataset": item.dataset,
            "attack_id": item.attack_id,
            "catalog_stix_id": item.catalog_stix_id,
            "catalog_name": item.catalog_name,
            "role": item.role,
            "confidence": item.confidence,
            "justification": item.justification,
            "declared_tactic": item.declared_tactic,
            "catalog_tactics_json": list(item.catalog_tactics),
            "valid_catalog_id": item.valid_catalog_id,
            "active_catalog_object": item.active_catalog_object,
            "tactic_consistent": item.tactic_consistent,
            "valid": item.valid,
        }

    def active_status(
        self,
        domain: str = "enterprise-attack",
    ) -> dict[str, Any] | None:
        with self._session_context_factory() as database_session:
            record = database_session.scalars(
                select(AttackCatalogVersionModel)
                .where(
                    AttackCatalogVersionModel.domain == domain,
                    AttackCatalogVersionModel.is_active.is_(True),
                )
                .order_by(AttackCatalogVersionModel.synced_at.desc())
            ).first()
            if record is None:
                return None
            valid_mapping_count = len(
                database_session.scalars(
                    select(RuleAttackMappingModel.id).where(
                        RuleAttackMappingModel.catalog_version_id == record.id,
                        RuleAttackMappingModel.valid.is_(True),
                    )
                ).all()
            )
            mapping_count = len(
                database_session.scalars(
                    select(RuleAttackMappingModel.id).where(
                        RuleAttackMappingModel.catalog_version_id == record.id
                    )
                ).all()
            )
            mapped_ids = set(
                database_session.scalars(
                    select(RuleAttackMappingModel.attack_id).where(
                        RuleAttackMappingModel.catalog_version_id == record.id,
                        RuleAttackMappingModel.valid.is_(True),
                    )
                ).all()
            )
            denominator = record.technique_count + record.subtechnique_count
            return {
                "catalog_id": record.id,
                "domain": record.domain,
                "display_name": record.display_name,
                "version": record.version,
                "collection_id": record.collection_id,
                "source_url": record.source_url,
                "source_modified": record.source_modified,
                "content_sha256": record.content_sha256,
                "object_count": record.object_count,
                "active_object_count": record.active_object_count,
                "relationship_count": record.relationship_count,
                "tactic_count": record.tactic_count,
                "technique_count": record.technique_count,
                "subtechnique_count": record.subtechnique_count,
                "object_type_counts": record.object_type_counts_json,
                "metadata": record.metadata_json,
                "catalog_awareness_percent": 100.0,
                "mapping_count": mapping_count,
                "valid_mapping_count": valid_mapping_count,
                "invalid_mapping_count": mapping_count - valid_mapping_count,
                "unique_mapped_attack_ids": len(mapped_ids),
                "rule_coverage_percent": (
                    round((len(mapped_ids) / denominator) * 100, 2) if denominator else 0.0
                ),
                "synced_at": record.synced_at,
            }

    def active_statuses(self) -> list[dict[str, Any]]:
        return [
            status
            for source in ALL_ATTACK_SOURCES
            if (status := self.active_status(source.domain)) is not None
        ]

    def technique_rows(
        self,
        domain: str = "enterprise-attack",
    ) -> list[dict[str, Any]]:
        with self._session_context_factory() as database_session:
            catalog_id = self._active_catalog_id(database_session, domain)
            if catalog_id is None:
                return []
            mapped_ids = set(
                database_session.scalars(
                    select(RuleAttackMappingModel.attack_id).where(
                        RuleAttackMappingModel.catalog_version_id == catalog_id,
                        RuleAttackMappingModel.valid.is_(True),
                    )
                ).all()
            )
            objects = database_session.scalars(
                select(AttackObjectModel)
                .where(
                    AttackObjectModel.catalog_version_id == catalog_id,
                    AttackObjectModel.object_type == "attack-pattern",
                    AttackObjectModel.active.is_(True),
                )
                .order_by(AttackObjectModel.attack_id)
            ).all()
            return [
                {
                    "attack_id": item.attack_id,
                    "name": item.name,
                    "type": "Sub-technique" if item.is_subtechnique else "Technique",
                    "is_subtechnique": item.is_subtechnique,
                    "parent_attack_id": item.parent_attack_id,
                    "tactics": ", ".join(item.tactic_shortnames_json or []),
                    "platforms": ", ".join(item.platforms_json or []),
                    "modified": item.modified,
                    "mapped_by_rule": item.attack_id in mapped_ids,
                    "coverage_state": (
                        "Evidence-backed rule coverage"
                        if item.attack_id in mapped_ids
                        else "Catalog awareness only"
                    ),
                    "external_url": item.external_url,
                }
                for item in objects
            ]

    def mapping_rows(
        self,
        domain: str = "enterprise-attack",
    ) -> list[dict[str, Any]]:
        with self._session_context_factory() as database_session:
            catalog_id = self._active_catalog_id(database_session, domain)
            if catalog_id is None:
                return []
            records = database_session.scalars(
                select(RuleAttackMappingModel)
                .where(RuleAttackMappingModel.catalog_version_id == catalog_id)
                .order_by(
                    RuleAttackMappingModel.detection_name,
                    RuleAttackMappingModel.attack_id,
                )
            ).all()
            return [
                {
                    "rule_id": item.rule_id,
                    "detection_name": item.detection_name,
                    "rule_version": item.rule_version,
                    "rule_status": item.rule_status,
                    "dataset": item.dataset,
                    "attack_id": item.attack_id,
                    "catalog_name": item.catalog_name,
                    "role": item.role,
                    "confidence": item.confidence,
                    "justification": item.justification,
                    "declared_tactic": item.declared_tactic,
                    "catalog_tactics": ", ".join(item.catalog_tactics_json or []),
                    "valid_catalog_id": item.valid_catalog_id,
                    "active_catalog_object": item.active_catalog_object,
                    "tactic_consistent": item.tactic_consistent,
                    "valid": item.valid,
                }
                for item in records
            ]

    def object_type_rows(
        self,
        domain: str = "enterprise-attack",
    ) -> list[dict[str, Any]]:
        status = self.active_status(domain)
        if status is None:
            return []
        return [
            {"object_type": key, "active_objects": value}
            for key, value in sorted(status["object_type_counts"].items())
        ]

    def navigator_json(self) -> bytes:
        catalog = self._load_catalog(
            source=ENTERPRISE_ATTACK_SOURCE,
            allow_network=False,
            force_download=False,
        )
        rules = RuleLoader(self._rule_directory).load(enabled_only=False)
        coverage: AttackCoverageReport = build_attack_coverage_report(catalog, rules)
        payload = build_navigator_layer(catalog, coverage)
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")

    @staticmethod
    def _active_catalog_id(
        database_session: Session,
        domain: str,
    ) -> int | None:
        return database_session.scalars(
            select(AttackCatalogVersionModel.id)
            .where(
                AttackCatalogVersionModel.domain == domain,
                AttackCatalogVersionModel.is_active.is_(True),
            )
            .order_by(AttackCatalogVersionModel.synced_at.desc())
        ).first()
