from __future__ import annotations

from pathlib import Path

import pytest

from attack.sources import (
    ALL_ATTACK_SOURCES,
    ALL_DOMAIN_EXPECTED_COUNTS,
    ENTERPRISE_ATTACK_SOURCE,
    ICS_ATTACK_SOURCE,
    MOBILE_ATTACK_SOURCE,
    AttackCatalogDownloadError,
    AttackCatalogSource,
    calculate_file_sha256,
    ensure_attack_bundle,
    validate_attack_bundle_file,
)


def test_all_official_attack_domains_are_pinned_to_v19_1() -> None:
    assert {source.domain for source in ALL_ATTACK_SOURCES} == {
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
    }
    assert all(source.version == "19.1" for source in ALL_ATTACK_SOURCES)
    assert ALL_DOMAIN_EXPECTED_COUNTS == {
        "domains": 3,
        "tactics": 39,
        "techniques": 378,
        "subtechniques": 540,
        "technique_records": 918,
    }
    assert (
        ENTERPRISE_ATTACK_SOURCE.expected_tactics,
        ENTERPRISE_ATTACK_SOURCE.expected_techniques,
        ENTERPRISE_ATTACK_SOURCE.expected_subtechniques,
    ) == (15, 222, 475)
    assert (
        MOBILE_ATTACK_SOURCE.expected_tactics,
        MOBILE_ATTACK_SOURCE.expected_techniques,
        MOBILE_ATTACK_SOURCE.expected_subtechniques,
    ) == (12, 77, 47)
    assert (
        ICS_ATTACK_SOURCE.expected_tactics,
        ICS_ATTACK_SOURCE.expected_techniques,
        ICS_ATTACK_SOURCE.expected_subtechniques,
    ) == (12, 79, 18)
    assert all(
        source.source_url.startswith(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
        )
        for source in ALL_ATTACK_SOURCES
    )


def test_offline_mode_fails_clearly_when_catalog_is_missing() -> None:
    source = AttackCatalogSource(
        domain="missing-test",
        display_name="Missing Test",
        version="1",
        collection_id="test",
        source_url="https://raw.githubusercontent.com/example/missing.json",
        modified="2026-01-01T00:00:00.000Z",
    )
    with pytest.raises(AttackCatalogDownloadError, match="Network synchronization is disabled"):
        ensure_attack_bundle(source, allow_network=False)


def test_sha256_is_stable(tmp_path: Path) -> None:
    path = tmp_path / "sample.json"
    path.write_bytes(b"threatlens")
    assert calculate_file_sha256(path) == calculate_file_sha256(path)


def test_bundle_identity_validation_rejects_wrong_collection(tmp_path: Path) -> None:
    source = AttackCatalogSource(
        domain="identity-test",
        display_name="Identity Test",
        version="19.1",
        collection_id="x-mitre-collection--expected",
        source_url=(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
            "identity-test/identity-test-19.1.json"
        ),
        modified="2026-05-12T14:00:00.188Z",
    )
    path = tmp_path / "bundle.json"
    path.write_text(
        '{"type":"bundle","objects":[{"type":"x-mitre-collection",'
        '"id":"x-mitre-collection--wrong","x_mitre_version":"19.1",'
        '"modified":"2026-05-12T14:00:00.188Z"}]}',
        encoding="utf-8",
    )
    with pytest.raises(AttackCatalogDownloadError, match="pinned collection"):
        validate_attack_bundle_file(path, source)


def test_bundle_identity_validation_accepts_exact_pinned_metadata(tmp_path: Path) -> None:
    source = AttackCatalogSource(
        domain="identity-test",
        display_name="Identity Test",
        version="19.1",
        collection_id="x-mitre-collection--expected",
        source_url=(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
            "identity-test/identity-test-19.1.json"
        ),
        modified="2026-05-12T14:00:00.188Z",
    )
    path = tmp_path / "bundle.json"
    path.write_text(
        '{"type":"bundle","objects":[{"type":"x-mitre-collection",'
        '"id":"x-mitre-collection--expected","x_mitre_version":"19.1",'
        '"modified":"2026-05-12T14:00:00.188Z"}]}',
        encoding="utf-8",
    )
    assert validate_attack_bundle_file(path, source) == 1
