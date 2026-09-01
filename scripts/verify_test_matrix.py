from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TestGroup:
    name: str
    expected_count: int
    paths: tuple[str, ...]


CORE_GROUP = TestGroup(
    name="core and multi-source analytics",
    expected_count=49,
    paths=(
        "tests/test_application_service.py",
        "tests/test_attack_catalog.py",
        "tests/test_attack_persistence.py",
        "tests/test_attack_sources.py",
        "tests/test_common_schema_connectors.py",
        "tests/test_core_pipeline.py",
        "tests/test_multisource_connectors.py",
        "tests/test_multisource_pipeline.py",
        "tests/test_persistence_service.py",
        "tests/test_report_generator.py",
        "tests/test_rule_engine.py",
    ),
)

V04_TO_V08_GROUP = TestGroup(
    name="v0.4 through v0.8 release regressions",
    expected_count=23,
    paths=(
        "tests/test_v04_persistence_metadata.py",
        "tests/test_v06_detection_catalog.py",
        "tests/test_v07_attack_mapping_migrations.py",
        "tests/test_v08_advanced_correlation.py",
        "tests/test_v08_attack_graph_export.py",
        "tests/test_v08_correlation_persistence.py",
        "tests/test_v08_entity_resolution.py",
        "tests/test_v08_migration_metadata.py",
    ),
)

V09_GROUP = TestGroup(
    name=(
        "v0.9-v0.9.5 authentication, RBAC, UAT remediation, concurrency, "
        "correctness and release integrity"
    ),
    expected_count=101,
    paths=(
        "tests/test_v09_migration_metadata.py",
        "tests/test_v09_navigation_rbac.py",
        "tests/test_v09_rbac.py",
        "tests/test_v09_security_api.py",
        "tests/test_v091_quality_security.py",
        "tests/test_v092_release_integrity.py",
        "tests/test_v093_correctness_security.py",
        "tests/test_v093_migration_metadata.py",
        "tests/test_v094_concurrency_configuration.py",
        "tests/test_v095_uat_remediation.py",
    ),
)

V010_GROUP = TestGroup(
    name="v0.10 grounded RAG, retrieval, grounding, security and integration",
    expected_count=32,
    paths=("tests/test_v010_grounded_rag.py",),
)

V011_GROUP = TestGroup(
    name=(
        "v0.11 adaptive routing, fallback, technique-binding, response-hardening and UI integration"
    ),
    expected_count=28,
    paths=("tests/test_v011_adaptive_rag.py",),
)


V0111_GROUP = TestGroup(
    name="v0.11.1 dependency security, built-in vector persistence and release closure",
    expected_count=12,
    paths=("tests/test_v0111_security_closure.py",),
)


V012_GROUP = TestGroup(
    name="v0.12 production web, PostgreSQL, pgvector, remote inference and deployment",
    expected_count=25,
    paths=("tests/test_v012_production_web.py", "tests/test_v012_feature_parity.py"),
)

RUNTIME_GROUP = TestGroup(
    name="pinned Windows runtime and test dependencies",
    expected_count=1,
    paths=("tests/test_runtime_dependencies.py",),
)


def _pytest_environment() -> dict[str, str]:
    """Run the governed matrix without unrelated globally installed pytest plugins."""

    environment = os.environ.copy()
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment.setdefault("PYTHONHASHSEED", "0")
    return environment


def _collect_count(group: TestGroup) -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *group.paths],
        check=False,
        capture_output=True,
        text=True,
        env=_pytest_environment(),
    )
    if result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"Test collection failed for group: {group.name}")
    return sum("::" in line for line in result.stdout.splitlines())


def _run_group(group: TestGroup) -> None:
    missing = [path for path in group.paths if not Path(path).is_file()]
    if missing:
        raise SystemExit(f"Missing tests for {group.name}: {', '.join(missing)}")
    collected = _collect_count(group)
    if collected != group.expected_count:
        raise SystemExit(
            f"{group.name}: expected {group.expected_count} tests, "
            f"collected {collected}. Update the governed test matrix."
        )
    print()
    print("=" * 72)
    print(f"Running {group.name} ({collected} tests)")
    print("=" * 72)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *group.paths],
        check=False,
        env=_pytest_environment(),
    )
    if result.returncode != 0:
        raise SystemExit(f"Test group failed: {group.name} (exit {result.returncode})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the ThreatLens test matrix in isolated processes so memory-heavy "
            "ATT&CK and API security suites cannot contaminate one another."
        )
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help=(
            "Skip the exact Streamlit/FastAPI/Starlette runtime pin test. "
            "Packaging environments use this only when those Windows runtime "
            "packages are intentionally unavailable."
        ),
    )
    args = parser.parse_args()

    groups = [
        CORE_GROUP,
        V04_TO_V08_GROUP,
        V09_GROUP,
        V010_GROUP,
        V011_GROUP,
        V0111_GROUP,
        V012_GROUP,
    ]
    if not args.skip_runtime:
        groups.append(RUNTIME_GROUP)

    for group in groups:
        _run_group(group)

    total = sum(group.expected_count for group in groups)
    print()
    print("=" * 72)
    print(f"ThreatLens governed test matrix passed: {total} tests.")
    print("=" * 72)


if __name__ == "__main__":
    main()
