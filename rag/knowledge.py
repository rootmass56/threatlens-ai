
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import AttackCatalogVersionModel, AttackObjectModel
from rag.models import KnowledgeChunk, KnowledgeDocument

ROOT_DIR = Path(__file__).resolve().parents[1]
GOVERNED_DOCS = (
    "docs/ATTACK_COVERAGE_POLICY.md",
    "docs/RULE_AUTHORING_GUIDE.md",
    "docs/MULTISOURCE_CONNECTORS.md",
    "docs/SECURITY_API_v0.9.md",
    "docs/ADVANCED_CORRELATION_v0.8.md",
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_governed_documents(root: Path = ROOT_DIR) -> list[KnowledgeDocument]:
    documents: list[KnowledgeDocument] = []
    for relative in GOVERNED_DOCS:
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        documents.append(
            KnowledgeDocument(
                source_id=f"doc:{relative}",
                title=path.stem.replace("_", " "),
                source_kind="threatlens_doc",
                version="0.10.0",
                trust_tier="governed",
                text=text,
                source_reference=relative,
                metadata={"sha256": _sha(text)},
            )
        )
    return documents


def load_rule_documents(root: Path = ROOT_DIR) -> list[KnowledgeDocument]:
    documents: list[KnowledgeDocument] = []
    for path in sorted((root / "rules").glob("**/*.yml")):
        if "fixtures" in path.parts:
            continue
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not payload.get("detection_name"):
            continue
        attack = payload.get("attack") or []
        response = payload.get("response") or {}
        text = "\n".join(
            [
                f"Detection: {payload.get('title')}",
                f"Detection name: {payload.get('detection_name')}",
                f"Description: {payload.get('description')}",
                f"Dataset: {(payload.get('logsource') or {}).get('dataset')}",
                f"Severity: {payload.get('severity')}; confidence: {payload.get('confidence')}",
                f"ATT&CK mappings: {json.dumps(attack, sort_keys=True)}",
                f"False positives: {json.dumps(payload.get('falsepositives') or [])}",
                f"Response recommendation: {response.get('recommendation') or ''}",
                f"Playbook: {response.get('playbook') or ''}",
            ]
        )
        relative = path.relative_to(root).as_posix()
        documents.append(
            KnowledgeDocument(
                source_id=f"rule:{payload['detection_name']}",
                title=str(payload.get("title") or payload["detection_name"]),
                source_kind="detection_rule",
                version=str(payload.get("version") or "1"),
                trust_tier="governed",
                text=text,
                source_reference=relative,
                metadata={
                    "detection_name": str(payload["detection_name"]),
                    "dataset": str((payload.get("logsource") or {}).get("dataset") or ""),
                    "status": str(payload.get("status") or ""),
                    "attack_ids": [
                        str(item.get("technique_id") or "").upper()
                        for item in attack
                        if isinstance(item, dict) and item.get("technique_id")
                    ],
                    "sha256": _sha(text),
                },
            )
        )
    return documents


def load_attack_documents(session: Session) -> list[KnowledgeDocument]:
    active_catalog = session.scalars(
        select(AttackCatalogVersionModel)
        .where(
            AttackCatalogVersionModel.domain.in_(("enterprise-attack", "enterprise")),
            AttackCatalogVersionModel.is_active.is_(True),
        )
        .order_by(AttackCatalogVersionModel.synced_at.desc())
    ).first()
    if active_catalog is None:
        return []
    objects = session.scalars(
        select(AttackObjectModel)
        .where(
            AttackObjectModel.catalog_version_id == active_catalog.id,
            AttackObjectModel.object_type == "attack-pattern",
            AttackObjectModel.active.is_(True),
            AttackObjectModel.attack_id.is_not(None),
        )
        .order_by(AttackObjectModel.attack_id)
    ).all()
    output: list[KnowledgeDocument] = []
    for item in objects:
        text = "\n".join(
            [
                f"MITRE ATT&CK {item.attack_id}: {item.name}",
                f"Description: {item.description or ''}",
                f"Tactics: {', '.join(item.tactic_shortnames_json or [])}",
                f"Platforms: {', '.join(item.platforms_json or [])}",
                f"Sub-technique: {item.is_subtechnique}",
                f"Parent technique: {item.parent_attack_id or ''}",
            ]
        )
        output.append(
            KnowledgeDocument(
                source_id=f"attack:{item.attack_id}",
                title=f"{item.attack_id} {item.name}",
                source_kind="attack_technique",
                version=active_catalog.version,
                trust_tier="official",
                text=text,
                source_reference=item.external_url or active_catalog.source_url,
                metadata={
                    "attack_id": item.attack_id,
                    "tactics": item.tactic_shortnames_json or [],
                    "platforms": item.platforms_json or [],
                    "catalog_sha256": active_catalog.content_sha256,
                },
            )
        )
    return output


def collect_documents(
    session: Session,
    root: Path = ROOT_DIR,
) -> list[KnowledgeDocument]:
    return (
        load_governed_documents(root) + load_rule_documents(root) + load_attack_documents(session)
    )


def _sections(text: str) -> Iterable[tuple[str, str]]:
    current = "document"
    buffer: list[str] = []
    for line in text.splitlines():
        heading = re.match(r"^#{1,4}\s+(.+?)\s*$", line)
        if heading and buffer:
            yield current, "\n".join(buffer).strip()
            buffer = []
        if heading:
            current = heading.group(1).strip()
        buffer.append(line)
    if buffer:
        yield current, "\n".join(buffer).strip()


def chunk_document(
    document: KnowledgeDocument,
    *,
    max_chars: int = 1800,
    overlap: int = 180,
) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    for section, section_text in _sections(document.text):
        start = 0
        part = 0
        while start < len(section_text):
            end = min(len(section_text), start + max_chars)
            text = section_text[start:end].strip()
            if not text:
                break
            payload = f"{document.source_id}\n{document.version}\n{section}\n{part}\n{text}"
            chunk_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    source_id=document.source_id,
                    title=document.title,
                    source_kind=document.source_kind,
                    version=document.version,
                    trust_tier=document.trust_tier,
                    section=section,
                    text=text,
                    source_reference=document.source_reference,
                    content_sha256=_sha(text),
                    metadata=document.metadata,
                )
            )
            if end >= len(section_text):
                break
            start = max(0, end - overlap)
            part += 1
    return chunks
