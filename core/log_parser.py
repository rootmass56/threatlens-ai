"""Backward-compatible parser entry points backed by the connector registry."""

from __future__ import annotations

from typing import Any

import pandas as pd

from core.connectors import LinuxAuthConnector
from core.schema import ParserResult


def parse_linux_auth_source(
    log_text: str | bytes,
    *,
    filename: str | None = None,
    options: dict[str, Any] | None = None,
) -> ParserResult:
    """Return complete schema-validated Linux parser output."""

    return LinuxAuthConnector().parse(log_text, filename=filename, options=options)


def parse_linux_auth_log(log_text: str) -> pd.DataFrame:
    """Return normalized events as a DataFrame for legacy callers."""

    return parse_linux_auth_source(log_text).to_dataframe()
