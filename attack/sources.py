from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
ATTACK_DATA_DIRECTORY = ROOT_DIR / "data" / "attack"


@dataclass(frozen=True, slots=True)
class AttackCatalogSource:
    """Pinned source metadata for one official ATT&CK catalog release."""

    domain: str
    display_name: str
    version: str
    collection_id: str
    source_url: str
    modified: str
    expected_sha256: str | None = None
    expected_tactics: int | None = None
    expected_techniques: int | None = None
    expected_subtechniques: int | None = None

    @property
    def filename(self) -> str:
        return f"{self.domain}-{self.version}.json"

    @property
    def bundle_path(self) -> Path:
        return ATTACK_DATA_DIRECTORY / self.filename

    @property
    def metadata_path(self) -> Path:
        return ATTACK_DATA_DIRECTORY / f"{self.domain}-{self.version}.metadata.json"


ENTERPRISE_ATTACK_SOURCE = AttackCatalogSource(
    domain="enterprise-attack",
    display_name="Enterprise ATT&CK",
    version="19.1",
    collection_id="x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
    source_url=(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
        "enterprise-attack/enterprise-attack-19.1.json"
    ),
    modified="2026-05-12T14:00:00.188Z",
    expected_sha256="bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
    expected_tactics=15,
    expected_techniques=222,
    expected_subtechniques=475,
)

MOBILE_ATTACK_SOURCE = AttackCatalogSource(
    domain="mobile-attack",
    display_name="Mobile ATT&CK",
    version="19.1",
    collection_id="x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
    source_url=(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
        "mobile-attack/mobile-attack-19.1.json"
    ),
    modified="2026-05-12T14:00:00.188Z",
    expected_sha256="423cbceb604770c8997845151fe7cc4813de01033b8cc50c84dd3bd0d96d8322",
    expected_tactics=12,
    expected_techniques=77,
    expected_subtechniques=47,
)

ICS_ATTACK_SOURCE = AttackCatalogSource(
    domain="ics-attack",
    display_name="ICS ATT&CK",
    version="19.1",
    collection_id="x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09",
    source_url=(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/"
        "ics-attack/ics-attack-19.1.json"
    ),
    modified="2026-05-12T14:00:00.188Z",
    expected_sha256="a91f659d6d03095e84089630b098edb2ed9d5cd5b1ea41369b27846cd32f2a43",
    expected_tactics=12,
    expected_techniques=79,
    expected_subtechniques=18,
)

ALL_ATTACK_SOURCES = (
    ENTERPRISE_ATTACK_SOURCE,
    MOBILE_ATTACK_SOURCE,
    ICS_ATTACK_SOURCE,
)
ATTACK_SOURCE_BY_DOMAIN = {source.domain: source for source in ALL_ATTACK_SOURCES}
ALL_DOMAIN_EXPECTED_COUNTS = {
    "domains": 3,
    "tactics": 39,
    "techniques": 378,
    "subtechniques": 540,
    "technique_records": 918,
}

ALLOWED_DOWNLOAD_HOSTS = {
    "raw.githubusercontent.com",
    "github.com",
    "attack.mitre.org",
}


class AttackCatalogDownloadError(RuntimeError):
    """Raised when an official ATT&CK bundle cannot be downloaded safely."""


def calculate_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_source_url(source: AttackCatalogSource) -> None:
    parsed = urlparse(source.source_url)
    if parsed.scheme != "https":
        raise AttackCatalogDownloadError("ATT&CK source must use HTTPS.")
    if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise AttackCatalogDownloadError(
            f"ATT&CK source host is not allowlisted: {parsed.hostname}"
        )


def validate_attack_bundle_file(
    path: Path,
    source: AttackCatalogSource | None = None,
) -> int:
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            payload = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise AttackCatalogDownloadError("Downloaded ATT&CK bundle is not valid JSON.") from error

    objects = payload.get("objects")
    if payload.get("type") != "bundle" or not isinstance(objects, list):
        raise AttackCatalogDownloadError("Downloaded file is not a STIX 2.1 bundle.")
    if not objects:
        raise AttackCatalogDownloadError("Downloaded ATT&CK bundle contains no objects.")

    if source is not None:
        collection = next(
            (
                item
                for item in objects
                if item.get("type") == "x-mitre-collection"
                and item.get("id") == source.collection_id
            ),
            None,
        )
        if collection is None:
            raise AttackCatalogDownloadError(
                f"ATT&CK bundle does not contain pinned collection {source.collection_id}."
            )
        if str(collection.get("x_mitre_version", "")) != source.version:
            raise AttackCatalogDownloadError(
                "ATT&CK bundle collection version does not match the pinned release."
            )
        if str(collection.get("modified", "")) != source.modified:
            raise AttackCatalogDownloadError(
                "ATT&CK bundle collection timestamp does not match pinned metadata."
            )
        if source.expected_sha256 is not None:
            content_sha256 = calculate_file_sha256(path)
            if content_sha256 != source.expected_sha256:
                raise AttackCatalogDownloadError(
                    "ATT&CK bundle SHA-256 does not match the pinned release."
                )

    return len(objects)


def download_attack_bundle(
    source: AttackCatalogSource = ENTERPRISE_ATTACK_SOURCE,
    *,
    destination: Path | None = None,
    force: bool = False,
    timeout_seconds: int = 120,
    retries: int = 3,
) -> Path:
    """Download a pinned official ATT&CK STIX bundle using an atomic replacement."""

    _validate_source_url(source)
    destination = destination or source.bundle_path
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not force:
        validate_attack_bundle_file(destination, source)
        return destination

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix=f"{source.domain}-{source.version}-",
                suffix=".json.part",
                dir=destination.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                with requests.get(
                    source.source_url,
                    stream=True,
                    timeout=(20, timeout_seconds),
                    allow_redirects=True,
                    headers={
                        "User-Agent": "ThreatLensAI/0.7 ATTACK-Catalog-Synchronizer",
                        "Accept": "application/json",
                    },
                ) as response:
                    response.raise_for_status()
                    final_host = urlparse(response.url).hostname
                    if final_host not in ALLOWED_DOWNLOAD_HOSTS:
                        raise AttackCatalogDownloadError(
                            f"ATT&CK download redirected to an untrusted host: {final_host}"
                        )
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            temporary.write(chunk)

            object_count = validate_attack_bundle_file(temporary_path, source)
            content_sha256 = calculate_file_sha256(temporary_path)
            os.replace(temporary_path, destination)
            metadata = {
                **asdict(source),
                "bundle_path": str(destination),
                "content_sha256": content_sha256,
                "object_count": object_count,
                "downloaded_at_epoch": time.time(),
            }
            source.metadata_path.write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return destination
        except (OSError, requests.RequestException, AttackCatalogDownloadError) as error:
            last_error = error
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(min(2**attempt, 8))

    raise AttackCatalogDownloadError(
        f"Unable to download {source.display_name} v{source.version}: {last_error}"
    )


def ensure_attack_bundle(
    source: AttackCatalogSource = ENTERPRISE_ATTACK_SOURCE,
    *,
    allow_network: bool = True,
    force: bool = False,
) -> Path:
    """Return a valid local bundle, downloading the pinned official release when needed."""

    if source.bundle_path.exists() and not force:
        validate_attack_bundle_file(source.bundle_path, source)
        return source.bundle_path
    if not allow_network:
        raise AttackCatalogDownloadError(
            f"ATT&CK bundle is missing: {source.bundle_path}. Network synchronization is disabled."
        )
    return download_attack_bundle(source, force=force)
