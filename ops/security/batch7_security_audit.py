from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    compose_text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    services = compose.get("services", {})
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    nginx = (ROOT / "frontend/nginx.conf").read_text(encoding="utf-8")
    middleware = (ROOT / "api/middleware.py").read_text(encoding="utf-8")
    startup = (ROOT / "scripts/start_production.sh").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    rbac = (ROOT / "api/rbac.py").read_text(encoding="utf-8")
    main = (ROOT / "api/main.py").read_text(encoding="utf-8")

    checks = {
        "application_non_root": "USER threatlens" in dockerfile,
        "container_no_new_privileges": compose_text.count("no-new-privileges:true") >= 6,
        "api_capabilities_dropped": services.get("api", {}).get("cap_drop") == ["ALL"],
        "worker_capabilities_dropped": services.get("worker", {}).get("cap_drop") == ["ALL"],
        "database_not_host_exposed": not services.get("postgres", {}).get("ports"),
        "redis_not_host_exposed": not services.get("redis", {}).get("ports"),
        "frontend_loopback_only": any(
            str(item).startswith("127.0.0.1:8080:")
            for item in services.get("frontend", {}).get("ports", [])
        ),
        "prometheus_loopback_only": any(
            str(item).startswith("127.0.0.1:9090:")
            for item in services.get("prometheus", {}).get("ports", [])
        ),
        "grafana_loopback_only": any(
            str(item).startswith("127.0.0.1:3000:")
            for item in services.get("grafana", {}).get("ports", [])
        ),
        "request_body_ceiling": "RequestBodyLimitMiddleware" in middleware,
        "conditional_hsts": "Strict-Transport-Security" in middleware,
        "coop_header": "Cross-Origin-Opener-Policy" in nginx,
        "corp_header": "Cross-Origin-Resource-Policy" in nginx,
        "nginx_version_hidden": "server_tokens off" in nginx,
        "uvicorn_server_header_disabled": "--no-server-header" in startup,
        "uvicorn_concurrency_bound": "--limit-concurrency" in startup,
        "batch7_env_ignored": ".env.*" in gitignore or ".env.batch7.local" in gitignore,
        "administrator_rbac": '"administrator"' in rbac and "ALL_PERMISSIONS" in rbac,
        "viewer_rbac": '"viewer"' in rbac,
        "analyst_rbac": '"analyst"' in rbac,
        "machine_ingestion_security": "X-ThreatLens-Ingest-Key" in main,
        "internal_metrics_not_api_prefixed": '@app.get("/internal/metrics"' in main,
    }

    failed = [name for name, passed in checks.items() if not passed]
    print(json.dumps({"checks": checks, "passed": len(checks) - len(failed), "failed": failed}, indent=2))
    require(not failed, "Batch-7 static security audit failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
