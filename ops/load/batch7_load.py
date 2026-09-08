from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import statistics
import time
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class Sample:
    ok: bool
    status: int
    seconds: float
    error: str | None = None


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(max(int(round((len(ordered) - 1) * q)), 0), len(ordered) - 1)
    return ordered[index]


def request_once(session: requests.Session, method: str, url: str, headers: dict[str, str]) -> Sample:
    started = time.perf_counter()
    try:
        response = session.request(method, url, headers=headers, timeout=20)
        elapsed = max(time.perf_counter() - started, 0.0)
        return Sample(200 <= response.status_code < 400, response.status_code, elapsed)
    except Exception as error:  # load tool must record failures instead of aborting the run
        return Sample(False, 0, max(time.perf_counter() - started, 0.0), type(error).__name__)


def login(base: str, username: str, password: str) -> str:
    response = requests.post(
        f"{base}/api/v1/auth/login",
        data={"username": username, "password": password},
        timeout=20,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatLens Batch-7 bounded HTTP load probe")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--scenario", choices=("live", "ready", "me"), default="live")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--min-success-rate", type=float, default=0.99)
    parser.add_argument("--max-p95-ms", type=float, default=1500.0)
    parser.add_argument("--json-output")
    args = parser.parse_args()

    if args.requests < 1 or args.requests > 20_000:
        parser.error("--requests must be between 1 and 20000")
    if args.concurrency < 1 or args.concurrency > 500:
        parser.error("--concurrency must be between 1 and 500")

    base = args.base.rstrip("/")
    headers: dict[str, str] = {}
    path = "/api/v1/health/live"
    if args.scenario == "ready":
        path = "/api/v1/health/ready"
    elif args.scenario == "me":
        username = os.getenv("THREATLENS_LOAD_USERNAME", "admin")
        password = os.getenv("THREATLENS_LOAD_PASSWORD", "")
        if not password:
            raise SystemExit("Set THREATLENS_LOAD_PASSWORD for the authenticated 'me' scenario.")
        token = login(base, username, password)
        headers["Authorization"] = f"Bearer {token}"
        path = "/api/v1/auth/me"

    session = requests.Session()
    url = base + path
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(request_once, session, "GET", url, headers) for _ in range(args.requests)]
        samples = [future.result() for future in concurrent.futures.as_completed(futures)]
    wall = max(time.perf_counter() - started, 1e-9)

    latencies_ms = [sample.seconds * 1000.0 for sample in samples]
    success = sum(1 for sample in samples if sample.ok)
    success_rate = success / len(samples)
    status_counts: dict[str, int] = {}
    for sample in samples:
        status_counts[str(sample.status)] = status_counts.get(str(sample.status), 0) + 1

    report = {
        "scenario": args.scenario,
        "url": url,
        "requests": len(samples),
        "concurrency": args.concurrency,
        "successes": success,
        "failures": len(samples) - success,
        "success_rate": round(success_rate, 6),
        "throughput_rps": round(len(samples) / wall, 3),
        "latency_ms": {
            "min": round(min(latencies_ms), 3),
            "mean": round(statistics.fmean(latencies_ms), 3),
            "p50": round(percentile(latencies_ms, 0.50), 3),
            "p95": round(percentile(latencies_ms, 0.95), 3),
            "p99": round(percentile(latencies_ms, 0.99), 3),
            "max": round(max(latencies_ms), 3),
        },
        "status_counts": status_counts,
        "thresholds": {
            "min_success_rate": args.min_success_rate,
            "max_p95_ms": args.max_p95_ms,
        },
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")

    passed = success_rate >= args.min_success_rate and report["latency_ms"]["p95"] <= args.max_p95_ms
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
