
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from attack.service import AttackCatalogService
from attack.sources import AttackCatalogSource
from database.base import Base
from database.models import (
    AttackCatalogVersionModel,
    AttackObjectModel,
    AttackRelationshipModel,
    RuleAttackMappingModel,
)

FIXTURE = Path("tests/fixtures/attack/enterprise-mini.json")
SOURCE = AttackCatalogSource(
    domain="enterprise-test",
    display_name="Enterprise ATT&CK Test",
    version="test",
    collection_id="x-mitre-collection--test",
    source_url="https://raw.githubusercontent.com/example/test.json",
    modified="2026-01-01T00:00:00.000Z",
    expected_tactics=2,
    expected_techniques=2,
    expected_subtechniques=2,
)


def _rule():
    mapping = SimpleNamespace(
        technique_id="T1000.001",
        tactic="Initial Access",
        role="primary",
        confidence=0.9,
        justification="Synthetic evidence-backed mapping for persistence tests.",
    )
    return SimpleNamespace(
        rule_id="11111111-1111-4111-8111-111111111111",
        detection_name="synthetic_rule",
        version=1,
        status=SimpleNamespace(value="stable"),
        logsource=SimpleNamespace(dataset="synthetic"),
        attack=[mapping],
    )


def test_catalog_sync_is_atomic_complete_and_idempotent(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'attack.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    @contextmanager
    def session_context():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    service = AttackCatalogService(session_context_factory=session_context)
    first = service.synchronize(
        source=SOURCE,
        allow_network=False,
        bundle_path=FIXTURE,
        rules=[_rule()],
        actor="pytest",
    )
    second = service.synchronize(
        source=SOURCE,
        allow_network=False,
        bundle_path=FIXTURE,
        rules=[_rule()],
        actor="pytest",
    )

    assert first.reused_catalog is False
    assert second.reused_catalog is True
    assert first.technique_count == 2
    assert first.subtechnique_count == 2

    with factory() as session:
        assert len(session.scalars(select(AttackCatalogVersionModel)).all()) == 1
        assert len(session.scalars(select(AttackObjectModel)).all()) == 11
        assert len(session.scalars(select(AttackRelationshipModel)).all()) == 3
        mappings = session.scalars(select(RuleAttackMappingModel)).all()
        assert len(mappings) == 1
        assert mappings[0].valid is True
        assert mappings[0].catalog_name == "Example Initial Sub-technique"

    status = service.active_status("enterprise-test")
    assert status is not None
    assert status["catalog_awareness_percent"] == 100.0
    assert status["unique_mapped_attack_ids"] == 1
    assert len(service.technique_rows("enterprise-test")) == 4
