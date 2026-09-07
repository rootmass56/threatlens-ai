from __future__ import annotations

import contextvars
import json
import logging
import math
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

_REQUEST_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "threatlens_request_id", default=None
)
_SERVICE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "threatlens_service", default=None
)


class JsonLogFormatter(logging.Formatter):
    """Single-line JSON formatter suitable for Docker/collector ingestion."""

    _reserved = frozenset(
        {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": getattr(record, "service", None) or _SERVICE.get(),
            "request_id": getattr(record, "request_id", None) or _REQUEST_ID.get(),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in self._reserved or key.startswith("_") or key in payload:
                continue
            if value is None or isinstance(value, (str, int, float, bool, list, dict, tuple)):
                payload[key] = value
            else:
                payload[key] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def configure_structured_logging(service: str, *, force: bool = False) -> None:
    """Configure root logging once for production JSON output.

    Tests and local tools can keep their own logging by leaving
    THREATLENS_STRUCTURED_LOGGING disabled. Batch-7 Compose enables it.
    """

    enabled = os.getenv("THREATLENS_STRUCTURED_LOGGING", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not (force or enabled):
        return

    level_name = os.getenv("THREATLENS_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    marker = "_threatlens_batch7_handler"
    if not any(getattr(handler, marker, False) for handler in root.handlers):
        handler = logging.StreamHandler()
        setattr(handler, marker, True)
        handler.setFormatter(JsonLogFormatter())
        root.handlers.clear()
        root.addHandler(handler)
    _SERVICE.set(service)
    logging.getLogger("threatlens.observability").info(
        "structured logging configured",
        extra={"event": "logging.configured", "service": service, "level_name": level_name},
    )


def set_request_context(request_id: str | None) -> contextvars.Token:
    return _REQUEST_ID.set(request_id)


def reset_request_context(token: contextvars.Token) -> None:
    _REQUEST_ID.reset(token)


@dataclass(frozen=True)
class HistogramSpec:
    buckets: tuple[float, ...]


class MetricsRegistry:
    """Small thread-safe Prometheus-compatible registry with bounded labels.

    No additional Python runtime dependency is required for Batch 7. The API
    process exposes an internal-only scrape endpoint and external Prometheus
    runs as a pinned container.
    """

    HTTP_DURATION = HistogramSpec(
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
    )

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._started = time.monotonic()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[
            tuple[str, tuple[tuple[str, str], ...]], dict[str, Any]
        ] = {}

    @staticmethod
    def _labels(labels: dict[str, Any] | None = None) -> tuple[tuple[str, str], ...]:
        if not labels:
            return ()
        normalized: list[tuple[str, str]] = []
        for key, value in sorted(labels.items()):
            key_text = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in str(key))[:64]
            value_text = str(value).replace("\\", "\\\\").replace("\n", " ")[:256]
            normalized.append((key_text, value_text))
        return tuple(normalized)

    def inc(self, name: str, value: float = 1.0, labels: dict[str, Any] | None = None) -> None:
        key = (name, self._labels(labels))
        with self._lock:
            self._counters[key] += float(value)

    def set_gauge(self, name: str, value: float, labels: dict[str, Any] | None = None) -> None:
        key = (name, self._labels(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(
        self,
        name: str,
        value: float,
        *,
        spec: HistogramSpec,
        labels: dict[str, Any] | None = None,
    ) -> None:
        key = (name, self._labels(labels))
        with self._lock:
            state = self._histograms.setdefault(
                key,
                {
                    "buckets": {bucket: 0 for bucket in spec.buckets},
                    "count": 0,
                    "sum": 0.0,
                },
            )
            state["count"] += 1
            state["sum"] += float(value)
            for bucket in spec.buckets:
                if value <= bucket:
                    state["buckets"][bucket] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = [
                {"name": name, "labels": dict(labels), "value": value}
                for (name, labels), value in sorted(self._counters.items())
            ]
            gauges = [
                {"name": name, "labels": dict(labels), "value": value}
                for (name, labels), value in sorted(self._gauges.items())
            ]
            histograms = []
            for (name, labels), state in sorted(self._histograms.items()):
                histograms.append(
                    {
                        "name": name,
                        "labels": dict(labels),
                        "count": state["count"],
                        "sum": state["sum"],
                        "buckets": {str(k): v for k, v in state["buckets"].items()},
                    }
                )
            return {
                "uptime_seconds": max(time.monotonic() - self._started, 0.0),
                "counters": counters,
                "gauges": gauges,
                "histograms": histograms,
            }

    @staticmethod
    def _render_labels(labels: Iterable[tuple[str, str]]) -> str:
        items = list(labels)
        if not items:
            return ""
        encoded = []
        for key, value in items:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            encoded.append(f'{key}="{escaped}"')
        return "{" + ",".join(encoded) + "}"

    def render_prometheus(self) -> str:
        lines = [
            "# HELP threatlens_process_uptime_seconds Seconds since this process metrics registry started.",
            "# TYPE threatlens_process_uptime_seconds gauge",
            f"threatlens_process_uptime_seconds {max(time.monotonic() - self._started, 0.0):.6f}",
        ]
        with self._lock:
            for (name, labels), value in sorted(self._counters.items()):
                lines.append(f"{name}{self._render_labels(labels)} {value:.12g}")
            for (name, labels), value in sorted(self._gauges.items()):
                if math.isfinite(value):
                    lines.append(f"{name}{self._render_labels(labels)} {value:.12g}")
            for (name, labels), state in sorted(self._histograms.items()):
                base_labels = dict(labels)
                for bucket, count in state["buckets"].items():
                    bucket_labels = self._labels({**base_labels, "le": str(bucket)})
                    lines.append(f"{name}_bucket{self._render_labels(bucket_labels)} {count}")
                inf_labels = self._labels({**base_labels, "le": "+Inf"})
                lines.append(f"{name}_bucket{self._render_labels(inf_labels)} {state['count']}")
                lines.append(f"{name}_count{self._render_labels(labels)} {state['count']}")
                lines.append(f"{name}_sum{self._render_labels(labels)} {state['sum']:.12g}")
        return "\n".join(lines) + "\n"


METRICS = MetricsRegistry()


def normalize_route(request: Any) -> str:
    route = request.scope.get("route") if hasattr(request, "scope") else None
    path = getattr(route, "path", None) or getattr(getattr(request, "url", None), "path", "unknown")
    text = str(path)
    if len(text) > 160:
        return text[:157] + "..."
    return text


def record_http_request(*, method: str, route: str, status_code: int, duration_seconds: float) -> None:
    status_class = f"{int(status_code) // 100}xx"
    labels = {"method": method.upper(), "route": route, "status_class": status_class}
    METRICS.inc("threatlens_http_requests_total", labels=labels)
    METRICS.observe(
        "threatlens_http_request_duration_seconds",
        duration_seconds,
        spec=MetricsRegistry.HTTP_DURATION,
        labels={"method": method.upper(), "route": route},
    )
    if status_code >= 500:
        METRICS.inc("threatlens_http_server_errors_total", labels={"route": route})
