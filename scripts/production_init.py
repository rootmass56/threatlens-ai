from __future__ import annotations

import argparse
import subprocess
import sys


def run(*args: str) -> None:
    result = subprocess.run([sys.executable, *args], check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize ThreatLens v0.12 production data.")
    parser.add_argument("--skip-index", action="store_true")
    args = parser.parse_args()
    run("-m", "alembic", "upgrade", "head")
    if not args.skip_index:
        run("-m", "scripts.index_rag_knowledge", "--force")
    print("ThreatLens AI v0.12 production initialization: PASS")


if __name__ == "__main__":
    main()
