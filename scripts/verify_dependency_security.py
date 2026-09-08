from __future__ import annotations

import argparse
import ast
import json
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from api.version import THREATLENS_VERSION
from scripts.release_inventory import ROOT_DIR

BASELINE_PATH = ROOT_DIR / "config" / "dependency_security_baseline.json"


def _load() -> dict:
    payload = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    if payload.get("release") != THREATLENS_VERSION:
        raise SystemExit(
            f"Dependency security baseline is not scoped to ThreatLens {THREATLENS_VERSION}."
        )
    return payload


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _exact_lines(path: Path) -> dict[str, str]:
    output: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(";", 1)[0].strip()
        if "==" not in line:
            continue
        name, pinned = line.split("==", 1)
        name = name.split("[", 1)[0].strip()
        output[_canonical(name)] = pinned.strip()
    return output


def _expected(payload: dict) -> dict[str, str]:
    merged: dict[str, str] = {}
    for section in ("build", "runtime", "development"):
        merged.update({_canonical(k): str(v) for k, v in payload[section].items()})
    return merged


def verify_source_contract(payload: dict) -> None:
    expected = _expected(payload)
    runtime = _exact_lines(ROOT_DIR / "requirements.txt")
    dev = _exact_lines(ROOT_DIR / "requirements-dev.txt")
    constraints = _exact_lines(ROOT_DIR / "constraints-windows-py311.txt")
    # BATCH7G_LINUX_SECURITY_OVERLAY_GUARD
    linux_constraints = _exact_lines(ROOT_DIR / "constraints-linux-py311.txt")
    expected_linux_constraints = {"msgpack": "1.2.1", "setuptools": "84.0.0"}
    if linux_constraints != expected_linux_constraints:
        raise SystemExit(
            "Linux security overlay differs from the reviewed Batch-7 constraints: "
            + json.dumps(
                {"expected": expected_linux_constraints, "actual": linux_constraints},
                sort_keys=True,
            )
        )
    pyproject = (ROOT_DIR / "pyproject.toml").read_text(encoding="utf-8")

    required_runtime = {_canonical(k): str(v) for k, v in payload["runtime"].items()}
    required_dev = {_canonical(k): str(v) for k, v in payload["development"].items()}
    if runtime != required_runtime:
        raise SystemExit(
            "requirements.txt differs from the reviewed dependency baseline: "
            + json.dumps({"expected": required_runtime, "actual": runtime}, sort_keys=True)
        )
    if dev != required_dev:
        raise SystemExit(
            "requirements-dev.txt differs from the reviewed dependency baseline: "
            + json.dumps({"expected": required_dev, "actual": dev}, sort_keys=True)
        )
    missing_constraints = {
        name: pinned for name, pinned in expected.items() if constraints.get(name) != pinned
    }
    if missing_constraints:
        raise SystemExit(
            "Windows constraints do not match the reviewed dependency baseline: "
            + json.dumps(missing_constraints, sort_keys=True)
        )

    source_files = [
        ROOT_DIR / "pyproject.toml",
        ROOT_DIR / "requirements.txt",
        ROOT_DIR / "requirements-dev.txt",
        ROOT_DIR / "constraints-windows-py311.txt",
    ]
    for forbidden in payload.get("forbidden_packages", []):
        pattern = re.compile(rf"(?im)^\s*[\"']?{re.escape(forbidden)}(?:\[.*?\])?\s*==")
        offenders = [path.name for path in source_files if pattern.search(path.read_text())]
        if offenders:
            raise SystemExit(f"Forbidden dependency {forbidden!r} remains in: {offenders}")
        if re.search(rf"(?m)^\s*import\s+{re.escape(forbidden)}\b", pyproject):
            raise SystemExit(f"Forbidden dependency import detected: {forbidden}")

    active_roots = (
        "api",
        "app",
        "attack",
        "config",
        "core",
        "correlation",
        "database",
        "rag",
        "rules",
        "scripts",
        "jobs",
        "advanced_soc",
    )
    forbidden_imports: list[str] = []
    for root_name in active_roots:
        root = ROOT_DIR / root_name
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except SyntaxError as error:
                relative = path.relative_to(ROOT_DIR)
                raise SystemExit(f"Cannot audit imports in {relative}: {error}") from error
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                forbidden = payload.get("forbidden_packages", [])
                if any(name.split(".", 1)[0] in forbidden for name in names):
                    forbidden_imports.append(path.relative_to(ROOT_DIR).as_posix())
    if forbidden_imports:
        raise SystemExit(
            "Forbidden dependency imports remain in active source: "
            + ", ".join(sorted(set(forbidden_imports)))
        )

    vector_source = (ROOT_DIR / "rag" / "vector_store.py").read_text(encoding="utf-8")
    if "class SQLiteVectorStore" not in vector_source:
        raise SystemExit("ThreatLens-owned SQLite vector store is missing.")

    streamlit_config = (ROOT_DIR / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    run_script = (ROOT_DIR / "scripts" / "run.ps1").read_text(encoding="utf-8")
    required_streamlit_controls = (
        'address = "127.0.0.1"',
        'showErrorDetails = "none"',
        "enableCORS = true",
        "enableXsrfProtection = true",
    )
    missing_ui_controls = [
        control for control in required_streamlit_controls if control not in streamlit_config
    ]
    if missing_ui_controls:
        raise SystemExit(
            "Local Streamlit security controls are missing: " + ", ".join(missing_ui_controls)
        )
    if "--server.address 127.0.0.1" not in run_script:
        raise SystemExit("scripts/run.ps1 must force the Streamlit UI to loopback-only binding.")


def verify_installed(payload: dict) -> None:
    expected = _expected(payload)
    actual: dict[str, str] = {}
    missing: list[str] = []
    for configured_name in [*payload["build"], *payload["runtime"], *payload["development"]]:
        canonical = _canonical(configured_name)
        try:
            actual[canonical] = version(configured_name)
        except PackageNotFoundError:
            missing.append(configured_name)
    if missing:
        raise SystemExit(
            "Reviewed dependencies are missing from the environment: " + ", ".join(missing)
        )
    mismatched = {
        name: {"expected": pinned, "actual": actual.get(name)}
        for name, pinned in expected.items()
        if actual.get(name) != pinned
    }
    if mismatched:
        raise SystemExit("Installed dependency versions differ: " + json.dumps(mismatched))
    for forbidden in payload.get("forbidden_packages", []):
        try:
            installed = version(forbidden)
        except PackageNotFoundError:
            continue
        raise SystemExit(f"Forbidden package {forbidden}=={installed} is installed in this venv.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify ThreatLens reviewed dependency security baseline."
    )
    parser.add_argument(
        "--installed",
        action="store_true",
        help="Also require the current environment to exactly match the reviewed pins.",
    )
    args = parser.parse_args()
    payload = _load()
    verify_source_contract(payload)
    if args.installed:
        verify_installed(payload)
    print("ThreatLens dependency security baseline verified: reviewed pins exact; ChromaDB absent.")


if __name__ == "__main__":
    main()
