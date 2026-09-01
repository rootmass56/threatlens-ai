from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from attack.sources import AttackCatalogSource, calculate_file_sha256


@dataclass(slots=True)
class AttackObjectRecord:
    """Normalized ATT&CK object while retaining the original STIX payload."""

    stix_id: str
    object_type: str
    attack_id: str | None
    name: str
    description: str | None
    created: str | None
    modified: str | None
    revoked: bool
    deprecated: bool
    is_subtechnique: bool
    parent_attack_id: str | None
    tactic_shortnames: tuple[str, ...]
    platforms: tuple[str, ...]
    external_url: str | None
    shortname: str | None
    raw: dict[str, Any] = field(repr=False)

    @property
    def active(self) -> bool:
        return not self.revoked and not self.deprecated


@dataclass(frozen=True, slots=True)
class AttackRelationshipRecord:
    stix_id: str
    relationship_type: str
    source_ref: str
    target_ref: str
    description: str | None
    created: str | None
    modified: str | None
    revoked: bool
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True, slots=True)
class AttackCatalogSummary:
    domain: str
    version: str
    content_sha256: str
    object_count: int
    active_object_count: int
    relationship_count: int
    tactic_count: int
    technique_count: int
    subtechnique_count: int
    mitigation_count: int
    group_count: int
    software_count: int
    campaign_count: int
    detection_strategy_count: int
    analytic_count: int
    data_component_count: int
    object_types: dict[str, int]

    @property
    def catalog_awareness_percent(self) -> float:
        return 100.0


class AttackCatalogValidationError(RuntimeError):
    """Raised when a pinned ATT&CK catalog violates required invariants."""


def _mitre_reference(payload: dict[str, Any]) -> dict[str, Any] | None:
    references = payload.get("external_references") or []
    for reference in references:
        if reference.get("source_name") == "mitre-attack":
            return reference
    for reference in references:
        if reference.get("external_id"):
            return reference
    return None


def _tuple_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _kill_chain_tactics(payload: dict[str, Any]) -> tuple[str, ...]:
    phases = payload.get("kill_chain_phases") or []
    return tuple(
        str(phase.get("phase_name", "")).strip()
        for phase in phases
        if phase.get("kill_chain_name") == "mitre-attack"
        and str(phase.get("phase_name", "")).strip()
    )


def _object_name(payload: dict[str, Any]) -> str:
    name = payload.get("name")
    if name:
        return str(name)
    reference = _mitre_reference(payload)
    if reference and reference.get("external_id"):
        return str(reference["external_id"])
    return str(payload.get("id", "Unnamed ATT&CK object"))


class AttackCatalog:
    """In-memory index over a complete official ATT&CK STIX 2.1 bundle."""

    def __init__(
        self,
        *,
        source: AttackCatalogSource,
        bundle_path: Path,
        raw_bundle: dict[str, Any],
    ) -> None:
        self.source = source
        self.bundle_path = bundle_path
        self.raw_bundle = raw_bundle
        self.content_sha256 = calculate_file_sha256(bundle_path)
        self._objects: list[AttackObjectRecord] = []
        self._relationships: list[AttackRelationshipRecord] = []
        self._by_stix_id: dict[str, AttackObjectRecord] = {}
        self._by_attack_id: dict[str, AttackObjectRecord] = {}
        self._matrix_tactic_order: tuple[str, ...] = ()
        self._parse()

    @classmethod
    def from_path(
        cls,
        bundle_path: Path,
        source: AttackCatalogSource,
    ) -> AttackCatalog:
        try:
            payload = json.loads(bundle_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            raise AttackCatalogValidationError(
                f"Unable to load ATT&CK bundle: {bundle_path}"
            ) from error
        if payload.get("type") != "bundle" or not isinstance(payload.get("objects"), list):
            raise AttackCatalogValidationError("ATT&CK file is not a STIX bundle.")
        return cls(source=source, bundle_path=bundle_path, raw_bundle=payload)

    def _parse(self) -> None:
        raw_objects = self.raw_bundle.get("objects", [])
        raw_relationships = [item for item in raw_objects if item.get("type") == "relationship"]
        parent_by_source_ref = {
            item.get("source_ref"): item.get("target_ref")
            for item in raw_relationships
            if item.get("relationship_type") == "subtechnique-of"
        }

        matrix_tactic_refs: list[str] = []
        for payload in raw_objects:
            if payload.get("type") == "x-mitre-matrix" and (
                payload.get("x_mitre_version") or payload.get("name") == "Enterprise ATT&CK"
            ):
                refs = payload.get("tactic_refs") or []
                if refs:
                    matrix_tactic_refs = [str(item) for item in refs]
                    break

        records_by_stix: dict[str, AttackObjectRecord] = {}
        for payload in raw_objects:
            object_type = str(payload.get("type", "unknown"))
            stix_id = str(payload.get("id", ""))
            if not stix_id:
                continue
            if object_type == "relationship":
                self._relationships.append(
                    AttackRelationshipRecord(
                        stix_id=stix_id,
                        relationship_type=str(payload.get("relationship_type", "")),
                        source_ref=str(payload.get("source_ref", "")),
                        target_ref=str(payload.get("target_ref", "")),
                        description=payload.get("description"),
                        created=payload.get("created"),
                        modified=payload.get("modified"),
                        revoked=bool(payload.get("revoked", False)),
                        raw=payload,
                    )
                )
                continue

            reference = _mitre_reference(payload)
            attack_id = (
                str(reference.get("external_id")).upper()
                if reference and reference.get("external_id")
                else None
            )
            external_url = str(reference.get("url")) if reference and reference.get("url") else None
            parent_ref = parent_by_source_ref.get(stix_id)
            record = AttackObjectRecord(
                stix_id=stix_id,
                object_type=object_type,
                attack_id=attack_id,
                name=_object_name(payload),
                description=payload.get("description"),
                created=payload.get("created"),
                modified=payload.get("modified"),
                revoked=bool(payload.get("revoked", False)),
                deprecated=bool(payload.get("x_mitre_deprecated", False)),
                is_subtechnique=bool(payload.get("x_mitre_is_subtechnique", False)),
                parent_attack_id=None,
                tactic_shortnames=_kill_chain_tactics(payload),
                platforms=_tuple_strings(payload.get("x_mitre_platforms")),
                external_url=external_url,
                shortname=(
                    str(payload.get("x_mitre_shortname"))
                    if payload.get("x_mitre_shortname")
                    else None
                ),
                raw=payload,
            )
            records_by_stix[stix_id] = record

        for record in records_by_stix.values():
            parent_ref = parent_by_source_ref.get(record.stix_id)
            if parent_ref and parent_ref in records_by_stix:
                record.parent_attack_id = records_by_stix[parent_ref].attack_id

        self._objects = list(records_by_stix.values())
        self._by_stix_id = records_by_stix
        self._by_attack_id = {
            record.attack_id: record for record in self._objects if record.attack_id is not None
        }
        self._matrix_tactic_order = tuple(
            records_by_stix[ref].shortname or records_by_stix[ref].name
            for ref in matrix_tactic_refs
            if ref in records_by_stix
        )

    @property
    def objects(self) -> tuple[AttackObjectRecord, ...]:
        return tuple(self._objects)

    @property
    def relationships(self) -> tuple[AttackRelationshipRecord, ...]:
        return tuple(self._relationships)

    @property
    def active_objects(self) -> tuple[AttackObjectRecord, ...]:
        return tuple(record for record in self._objects if record.active)

    @property
    def tactic_order(self) -> tuple[str, ...]:
        if self._matrix_tactic_order:
            return self._matrix_tactic_order
        return tuple(
            record.shortname or record.name
            for record in sorted(
                self.active_objects_by_type("x-mitre-tactic"),
                key=lambda item: item.attack_id or item.name,
            )
        )

    def active_objects_by_type(self, object_type: str) -> tuple[AttackObjectRecord, ...]:
        return tuple(
            record
            for record in self._objects
            if record.object_type == object_type and record.active
        )

    def get_by_attack_id(self, attack_id: str) -> AttackObjectRecord | None:
        return self._by_attack_id.get(attack_id.strip().upper())

    def get_by_stix_id(self, stix_id: str) -> AttackObjectRecord | None:
        return self._by_stix_id.get(stix_id)

    def active_attack_patterns(self) -> tuple[AttackObjectRecord, ...]:
        return self.active_objects_by_type("attack-pattern")

    def active_techniques(self) -> tuple[AttackObjectRecord, ...]:
        return tuple(item for item in self.active_attack_patterns() if not item.is_subtechnique)

    def active_subtechniques(self) -> tuple[AttackObjectRecord, ...]:
        return tuple(item for item in self.active_attack_patterns() if item.is_subtechnique)

    def tactic_records(self) -> tuple[AttackObjectRecord, ...]:
        records = self.active_objects_by_type("x-mitre-tactic")
        order = {value: index for index, value in enumerate(self.tactic_order)}
        return tuple(
            sorted(
                records,
                key=lambda item: order.get(item.shortname or item.name, 10_000),
            )
        )

    def summary(self) -> AttackCatalogSummary:
        active = self.active_objects
        object_types = Counter(record.object_type for record in active)
        software_count = object_types.get("malware", 0) + object_types.get("tool", 0)
        return AttackCatalogSummary(
            domain=self.source.domain,
            version=self.source.version,
            content_sha256=self.content_sha256,
            object_count=len(self.raw_bundle.get("objects", [])),
            active_object_count=len(active),
            relationship_count=len(self._relationships),
            tactic_count=len(self.tactic_records()),
            technique_count=len(self.active_techniques()),
            subtechnique_count=len(self.active_subtechniques()),
            mitigation_count=object_types.get("course-of-action", 0),
            group_count=object_types.get("intrusion-set", 0),
            software_count=software_count,
            campaign_count=object_types.get("campaign", 0),
            detection_strategy_count=object_types.get("x-mitre-detection-strategy", 0),
            analytic_count=object_types.get("x-mitre-analytic", 0),
            data_component_count=object_types.get("x-mitre-data-component", 0),
            object_types=dict(sorted(object_types.items())),
        )

    def validate_expected_counts(self) -> AttackCatalogSummary:
        summary = self.summary()
        expected = {
            "tactics": self.source.expected_tactics,
            "techniques": self.source.expected_techniques,
            "subtechniques": self.source.expected_subtechniques,
        }
        actual = {
            "tactics": summary.tactic_count,
            "techniques": summary.technique_count,
            "subtechniques": summary.subtechnique_count,
        }
        mismatches = {
            key: {"expected": expected[key], "actual": actual[key]}
            for key in expected
            if expected[key] is not None and expected[key] != actual[key]
        }
        if mismatches:
            raise AttackCatalogValidationError(
                f"ATT&CK v{self.source.version} catalog count mismatch: {mismatches}"
            )
        return summary

    def technique_rows(self) -> list[dict[str, Any]]:
        tactic_name_by_shortname = {
            record.shortname: record.name for record in self.tactic_records() if record.shortname
        }
        rows: list[dict[str, Any]] = []
        for record in sorted(
            self.active_attack_patterns(), key=lambda item: item.attack_id or item.name
        ):
            rows.append(
                {
                    "attack_id": record.attack_id,
                    "name": record.name,
                    "is_subtechnique": record.is_subtechnique,
                    "parent_attack_id": record.parent_attack_id,
                    "tactics": ", ".join(
                        tactic_name_by_shortname.get(item, item)
                        for item in record.tactic_shortnames
                    ),
                    "tactic_shortnames": ", ".join(record.tactic_shortnames),
                    "platforms": ", ".join(record.platforms),
                    "modified": record.modified,
                    "external_url": record.external_url,
                }
            )
        return rows

    def objects_by_attack_prefix(self) -> dict[str, list[AttackObjectRecord]]:
        groups: dict[str, list[AttackObjectRecord]] = defaultdict(list)
        for record in self.active_objects:
            if record.attack_id:
                prefix = "".join(character for character in record.attack_id if character.isalpha())
                groups[prefix].append(record)
        return dict(groups)

    def modified_after(self, timestamp: datetime) -> tuple[AttackObjectRecord, ...]:
        selected: list[AttackObjectRecord] = []
        for record in self.active_objects:
            if not record.modified:
                continue
            try:
                modified = datetime.fromisoformat(record.modified.replace("Z", "+00:00"))
            except ValueError:
                continue
            if modified > timestamp:
                selected.append(record)
        return tuple(selected)


def active_attack_ids(records: Iterable[AttackObjectRecord]) -> set[str]:
    return {record.attack_id for record in records if record.attack_id and record.active}
