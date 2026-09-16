from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin


def request(url: str, *, accept_json: bool = False) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "User-Agent": "ThreatLens-Phase9-Verifier/1.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if accept_json:
        headers["Accept"] = "application/json"

    req = urllib.request.Request(url, headers=headers, method="GET")
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=context) as response:
            return (
                int(response.status),
                {str(k).lower(): str(v) for k, v in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as error:
        return (
            int(error.code),
            {str(k).lower(): str(v) for k, v in error.headers.items()},
            error.read(),
        )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    base = args.url.rstrip("/") + "/"
    require(base.startswith("https://"), "Public demo URL must use HTTPS.")
    require(".trycloudflare.com/" in base, "Public demo URL must be a TryCloudflare Quick Tunnel URL.")

    home_status, home_headers, home_body = request(base)
    require(home_status == 200, f"Home returned HTTP {home_status}, expected 200.")
    require("text/html" in home_headers.get("content-type", "").lower(), "Home is not HTML.")

    required_home_headers = {
        "strict-transport-security": "max-age=",
        "x-frame-options": "deny",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "content-security-policy": "default-src",
    }
    for name, fragment in required_home_headers.items():
        value = home_headers.get(name, "")
        require(fragment.lower() in value.lower(), f"Missing/invalid public header {name}: {value!r}")

    live_status, live_headers, live_body = request(urljoin(base, "api/v1/health/live"), accept_json=True)
    require(live_status == 200, f"Same-origin API live endpoint returned HTTP {live_status}.")
    require("application/json" in live_headers.get("content-type", "").lower(), "API live endpoint is not JSON.")
    live = json.loads(live_body.decode("utf-8"))
    require(live.get("status") == "ok", f"API live status is not ok: {live!r}")
    require("max-age=" in live_headers.get("strict-transport-security", "").lower(), "API HSTS is missing.")

    auth_status, auth_headers, _ = request(urljoin(base, "api/v1/auth/me"), accept_json=True)
    require(auth_status == 401, f"Unauthenticated /api/v1/auth/me returned HTTP {auth_status}, expected 401.")

    metrics_status, metrics_headers, metrics_body = request(urljoin(base, "internal/metrics"))
    require(metrics_status == 200, f"/internal/metrics boundary probe returned HTTP {metrics_status}.")
    require("text/html" in metrics_headers.get("content-type", "").lower(), "/internal/metrics did not stay on the frontend boundary.")
    metrics_text = metrics_body.decode("utf-8", errors="replace")
    require("# HELP threatlens_" not in metrics_text, "Prometheus metrics appear exposed through the public frontend.")

    result = {
        "status": "PASS",
        "public_url": base.rstrip("/"),
        "https": True,
        "frontend_security_headers": "PASS",
        "same_origin_api": "PASS",
        "api_live_status": live.get("status"),
        "unauthenticated_auth_me": 401,
        "internal_metrics_exposed": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
