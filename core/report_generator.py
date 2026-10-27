from __future__ import annotations

import ast
import html
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

PROJECT_NAME = "ThreatLens AI"
REPORT_TITLE = "Incident Investigation Report"
REPORT_VERSION = "3.1"
REPORT_CLASSIFICATION = "INTERNAL - AUTHORIZED SECURITY OPERATIONS USE"

BODY_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
_FONTS_REGISTERED = False

NAVY = colors.HexColor("#071C2C")
NAVY_LIGHT = colors.HexColor("#0E3048")
TEAL = colors.HexColor("#00A99D")
INK = colors.HexColor("#162735")
MUTED = colors.HexColor("#5C6F7E")
LINE = colors.HexColor("#D5E0E7")
SURFACE = colors.HexColor("#F3F7F9")
SURFACE_ALT = colors.HexColor("#EAF2F5")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#9B1C31"),
    "high": colors.HexColor("#C34A2C"),
    "medium": colors.HexColor("#C47F00"),
    "low": colors.HexColor("#276B8A"),
    "informational": colors.HexColor("#607D8B"),
    "unknown": MUTED,
}
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}
_MISSING_TEXT_VALUES = {"", "<na>", "nan", "nat", "none", "null"}


def _register_report_fonts() -> None:
    """Embed deterministic fonts so the report renders consistently everywhere."""
    global BODY_FONT, BOLD_FONT, _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    if regular.exists() and bold.exists():
        pdfmetrics.registerFont(TTFont("ThreatLensSans", str(regular)))
        pdfmetrics.registerFont(TTFont("ThreatLensSans-Bold", str(bold)))
        BODY_FONT = "ThreatLensSans"
        BOLD_FONT = "ThreatLensSans-Bold"
    _FONTS_REGISTERED = True


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _MISSING_TEXT_VALUES
    if isinstance(value, (dict, list, set, tuple)):
        return False
    try:
        return bool(pd.isna(value))
    except (TypeError, ValueError):
        return False


def _display_value(value: Any, default: str = "Not available") -> str:
    if _is_missing(value):
        return default
    return str(value).strip()


def _text(value: Any, default: str = "Not available") -> str:
    return escape(_display_value(value, default))


def _paragraph(value: Any, style: ParagraphStyle, default: str = "Not available") -> Paragraph:
    return Paragraph(_text(value, default), style)


def _citation_excerpt(value: Any, *, max_chars: int = 320) -> str:
    """Make untrusted source snippets readable without changing persisted evidence."""
    raw = html.unescape(_display_value(value))
    plain = re.sub(r"</?code\b[^>]*>", "", raw, flags=re.IGNORECASE)
    plain = re.sub(r"<br\s*/?>", " ", plain, flags=re.IGNORECASE)
    plain = re.sub(r"\[([^\]]+)\]\((?:[^()]|\([^()]*\))*\)", r"\1", plain)
    plain = re.sub(r"\s+", " ", plain.replace("`", "")).strip()
    if len(plain) <= max_chars:
        return plain
    prefix = plain[:max_chars].rsplit(" ", 1)[0] or plain[:max_chars]
    sentence_end = prefix.rfind(". ")
    if sentence_end >= max_chars // 2:
        return prefix[:sentence_end + 1]
    return prefix.rstrip(" ,;:") + "..."


def _status_label(value: Any) -> str:
    return _display_value(value, "Open").replace("_", " ").title()


def _format_timestamp(value: Any, default: str = "Not available") -> str:
    if _is_missing(value):
        return default
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(parsed):
        return _display_value(value, default)
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_number(value: Any, digits: int = 2, default: str = "Not available") -> str:
    if _is_missing(value):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return _display_value(value, default)
    if number.is_integer():
        return str(int(number))
    return f"{number:.{digits}f}".rstrip("0").rstrip(".")


def _evidence_items(value: Any) -> list[str]:
    if _is_missing(value):
        return []
    parsed = value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("[", "(", "{")):
            try:
                parsed = ast.literal_eval(stripped)
            except (SyntaxError, ValueError):
                parsed = stripped
    if isinstance(parsed, dict):
        iterable: Iterable[Any] = parsed.values()
    elif isinstance(parsed, (list, set, tuple)):
        iterable = parsed
    else:
        iterable = [parsed]
    return [text for item in iterable if not _is_missing(item) and (text := str(item).strip())]


def _evidence_summary(value: Any) -> str:
    items = _evidence_items(value)
    count = len(items)
    if count == 0:
        return "No linked events"
    noun = "event" if count == 1 else "events"
    prefixes = [item if len(item) <= 8 else item[:8] for item in items[:2]]
    trace = ", ".join(prefixes)
    if count > 2:
        trace = f"{trace}, +{count - 2} more"
    return f"{count} linked {noun}: {trace}"


def _series_values(frame: pd.DataFrame, column: str) -> list[str]:
    if frame.empty or column not in frame.columns:
        return []
    return [str(value).strip() for value in frame[column] if not _is_missing(value) and str(value).strip()]


def _severity_counts(alerts_df: pd.DataFrame, incidents_df: pd.DataFrame) -> Counter[str]:
    values = _series_values(alerts_df, "severity") or _series_values(incidents_df, "severity")
    return Counter(value.lower() for value in values)


def _highest_severity(alerts_df: pd.DataFrame, incidents_df: pd.DataFrame) -> str:
    counts = _severity_counts(alerts_df, incidents_df)
    if not counts:
        return "None"
    return max(counts, key=lambda value: SEVERITY_ORDER.get(value, 0)).title()


def _numeric_summary(frame: pd.DataFrame, column: str) -> tuple[float | None, float | None]:
    if frame.empty or column not in frame.columns:
        return None, None
    values = pd.to_numeric(frame[column], errors="coerce").dropna()
    if values.empty:
        return None, None
    return float(values.max()), float(values.mean())


def _analysis_window(events_df: pd.DataFrame, alerts_df: pd.DataFrame) -> tuple[str, str]:
    values: list[Any] = []
    for frame in (events_df, alerts_df):
        if not frame.empty and "timestamp" in frame.columns:
            values.extend(frame["timestamp"].tolist())
    parsed = pd.to_datetime(pd.Series(values, dtype="object"), errors="coerce", utc=True).dropna()
    if parsed.empty:
        return "Not available", "Not available"
    return _format_timestamp(parsed.min()), _format_timestamp(parsed.max())


def _telemetry_sources(events_df: pd.DataFrame) -> list[str]:
    for column in ("connector_id", "ingest_source", "dataset"):
        values = sorted(set(_series_values(events_df, column)))
        if values:
            return values
    return []


def _attack_techniques(alerts_df: pd.DataFrame, incidents_df: pd.DataFrame) -> list[str]:
    values: set[str] = set()
    for frame in (alerts_df, incidents_df):
        for column in ("mitre_technique_id", "attack_technique_id"):
            values.update(_series_values(frame, column))
    return sorted(values)


def _report_identifier(session_uuid: str | None, generated_at: datetime) -> str:
    session_component = "UNSCOPED"
    if session_uuid:
        compact = "".join(character for character in session_uuid.upper() if character.isalnum())
        session_component = compact[:8] or "UNSCOPED"
    return f"TL-IR-{generated_at:%Y%m%d}-{session_component}"


def _report_metrics(events_df: pd.DataFrame, alerts_df: pd.DataFrame, incidents_df: pd.DataFrame) -> dict[str, Any]:
    sources = _telemetry_sources(events_df)
    max_risk, average_risk = _numeric_summary(incidents_df, "risk_score")
    if max_risk is None:
        max_risk, average_risk = _numeric_summary(alerts_df, "risk_score")
    _, average_confidence = _numeric_summary(alerts_df, "confidence")
    if average_confidence is None:
        _, average_confidence = _numeric_summary(incidents_df, "confidence")
    window_start, window_end = _analysis_window(events_df, alerts_df)
    techniques = _attack_techniques(alerts_df, incidents_df)
    status_counts = Counter(_status_label(value) for value in _series_values(incidents_df, "status"))
    return {
        "events": len(events_df),
        "alerts": len(alerts_df),
        "incidents": len(incidents_df),
        "sources": sources,
        "source_count": len(sources),
        "highest_severity": _highest_severity(alerts_df, incidents_df),
        "severity_counts": _severity_counts(alerts_df, incidents_df),
        "max_risk": max_risk,
        "average_risk": average_risk,
        "average_confidence": average_confidence,
        "window_start": window_start,
        "window_end": window_end,
        "techniques": techniques,
        "status_counts": status_counts,
    }


def _build_styles():
    styles = getSampleStyleSheet()
    styles["BodyText"].fontName = BODY_FONT
    styles["BodyText"].fontSize = 8.3
    styles["BodyText"].leading = 10.8
    styles["BodyText"].textColor = INK
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName=BOLD_FONT, fontSize=22, leading=25, alignment=TA_LEFT, textColor=WHITE, spaceAfter=4))
    styles.add(ParagraphStyle(name="ReportSubtitle", parent=styles["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#C8E8EA")))
    styles.add(ParagraphStyle(name="Eyebrow", parent=styles["BodyText"], fontName=BOLD_FONT, fontSize=6.8, leading=8.5, textColor=TEAL, spaceAfter=2))
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"], fontName=BOLD_FONT, fontSize=14, leading=17, textColor=NAVY, spaceBefore=3, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle(name="SubsectionHeading", parent=styles["Heading3"], fontName=BOLD_FONT, fontSize=10, leading=12, textColor=NAVY_LIGHT, spaceBefore=5, spaceAfter=4, keepWithNext=True))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.2, leading=9))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["BodyText"], fontSize=6.2, leading=7.6))
    styles.add(ParagraphStyle(name="SmallInverse", parent=styles["Small"], textColor=WHITE))
    styles.add(ParagraphStyle(name="MetaLabel", parent=styles["Small"], fontName=BOLD_FONT, fontSize=6.2, leading=7.6, textColor=MUTED))
    styles.add(ParagraphStyle(name="AnswerLabel", parent=styles["MetaLabel"], keepWithNext=True))
    styles.add(ParagraphStyle(name="TechniqueHeading", parent=styles["Small"], fontName=BOLD_FONT, textColor=NAVY_LIGHT, spaceBefore=3, spaceAfter=2, keepWithNext=True))
    styles.add(ParagraphStyle(name="CitationKey", parent=styles["Tiny"], wordWrap="CJK"))
    styles.add(ParagraphStyle(name="MetricValue", parent=styles["BodyText"], fontName=BOLD_FONT, fontSize=17, leading=19, alignment=TA_CENTER, textColor=NAVY))
    styles.add(ParagraphStyle(name="MetricLabel", parent=styles["Small"], fontName=BOLD_FONT, fontSize=6.2, leading=7.5, alignment=TA_CENTER, textColor=MUTED))
    styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontSize=7.8, leading=10.3, textColor=INK))
    styles.add(ParagraphStyle(name="BulletBody", parent=styles["BodyText"], leftIndent=12, firstLineIndent=-8, bulletIndent=2, spaceAfter=3))
    return styles


def _table_style(*, compact: bool = False) -> TableStyle:
    vertical_padding = 3 if compact else 5
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), BOLD_FONT), ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ("LEADING", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TEAL), ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), vertical_padding), ("BOTTOMPADDING", (0, 0), (-1, -1), vertical_padding),
    ])


def _key_value_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE), ("BACKGROUND", (0, 0), (0, -1), SURFACE_ALT),
        ("FONTNAME", (0, 0), (0, -1), BOLD_FONT), ("TEXTCOLOR", (0, 0), (0, -1), NAVY_LIGHT),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])


def _draw_page(canvas, document) -> None:
    canvas.saveState()
    width, height = document.pagesize
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 11 * mm, width, 11 * mm, stroke=0, fill=1)
    canvas.setFillColor(TEAL)
    canvas.rect(0, height - 11 * mm, 4 * mm, 11 * mm, stroke=0, fill=1)
    canvas.setFont(BOLD_FONT, 8)
    canvas.setFillColor(WHITE)
    canvas.drawString(10 * mm, height - 7 * mm, PROJECT_NAME)
    canvas.setFont(BODY_FONT, 6.5)
    canvas.setFillColor(colors.HexColor("#C8E8EA"))
    canvas.drawRightString(width - 10 * mm, height - 7 * mm, REPORT_CLASSIFICATION)
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(14 * mm, 11 * mm, width - 14 * mm, 11 * mm)
    canvas.setFont(BODY_FONT, 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(14 * mm, 6.5 * mm, f"{PROJECT_NAME} | {REPORT_TITLE} v{REPORT_VERSION}")
    canvas.drawCentredString(width / 2, 6.5 * mm, "Generated from persisted investigation evidence")
    canvas.drawRightString(width - 14 * mm, 6.5 * mm, f"Page {document.page}")
    canvas.restoreState()


def _metadata_cell(label: str, value: Any, styles) -> Paragraph:
    return Paragraph(f'<font color="#5C6F7E" size="6"><b>{escape(label.upper())}</b></font><br/><font color="#162735" size="8"><b>{_text(value)}</b></font>', styles["Small"])


def _title_panel(analysis_name: str | None, report_id: str, styles) -> Table:
    left = [Paragraph("THREATLENS SECURITY OPERATIONS", styles["Eyebrow"]), Paragraph(REPORT_TITLE, styles["ReportTitle"]), Paragraph(_text(analysis_name, "Current Analysis"), styles["ReportSubtitle"])]
    right = Table([[Paragraph("DOCUMENT STATUS", styles["MetaLabel"])], [Paragraph("FINAL - SYSTEM GENERATED", styles["SmallInverse"])], [Paragraph("REPORT ID", styles["MetaLabel"])], [Paragraph(_text(report_id), styles["SmallInverse"])]], colWidths=[72 * mm])
    right.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY_LIGHT), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#2C596D")), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    panel = Table([[left, right]], colWidths=[182 * mm, 72 * mm])
    panel.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.8, NAVY), ("LEFTPADDING", (0, 0), (0, 0), 12), ("RIGHTPADDING", (0, 0), (0, 0), 12), ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11), ("LEFTPADDING", (1, 0), (1, 0), 0), ("RIGHTPADDING", (1, 0), (1, 0), 8)]))
    return panel


def _metadata_grid(session_uuid: str | None, analyst: str | None, generated_at: datetime, metrics: dict[str, Any], styles) -> Table:
    rows = [[_metadata_cell("Session UUID", session_uuid, styles), _metadata_cell("Prepared by", analyst or "Not specified", styles), _metadata_cell("Generated", _format_timestamp(generated_at), styles), _metadata_cell("Classification", "Internal", styles)], [_metadata_cell("Investigation start", metrics["window_start"], styles), _metadata_cell("Investigation end", metrics["window_end"], styles), _metadata_cell("Telemetry sources", metrics["source_count"], styles), _metadata_cell("Report version", REPORT_VERSION, styles)]]
    table = Table(rows, colWidths=[70 * mm, 52 * mm, 70 * mm, 62 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WHITE), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return table


def _metric_cards(metrics: dict[str, Any], styles) -> Table:
    cards = [(str(metrics["events"]), "NORMALIZED EVENTS"), (str(metrics["alerts"]), "DETECTION ALERTS"), (str(metrics["incidents"]), "CORRELATED INCIDENTS"), (str(metrics["source_count"]), "TELEMETRY SOURCES"), (str(metrics["highest_severity"]).upper(), "HIGHEST SEVERITY")]
    cells = [[Paragraph(_text(value), styles["MetricValue"]), Paragraph(_text(label), styles["MetricLabel"])] for value, label in cards]
    table = Table([cells], colWidths=[50.8 * mm] * 5)
    commands: list[tuple[Any, ...]] = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), SURFACE), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LINEABOVE", (0, 0), (-2, 0), 2.2, TEAL)]
    commands.append(("LINEABOVE", (-1, 0), (-1, 0), 2.2, SEVERITY_COLORS.get(str(metrics["highest_severity"]).lower(), MUTED)))
    table.setStyle(TableStyle(commands))
    return table


def _overview_table(metrics: dict[str, Any], styles) -> Table:
    severity_summary = ", ".join(f"{name.title()}: {count}" for name, count in sorted(metrics["severity_counts"].items(), key=lambda item: SEVERITY_ORDER.get(item[0], 0), reverse=True)) or "No alert severity data"
    status_summary = ", ".join(f"{name}: {count}" for name, count in sorted(metrics["status_counts"].items())) or "No correlated incidents"
    rows = [
        ["Risk posture", _paragraph(f"Highest severity: {metrics['highest_severity']} | Maximum risk score: {_format_number(metrics['max_risk'])} | Average detection confidence: {_format_number(metrics['average_confidence'])}", styles["Small"])],
        ["Severity distribution", _paragraph(severity_summary, styles["Small"])],
        ["Incident workflow", _paragraph(status_summary, styles["Small"])],
        ["Telemetry coverage", _paragraph(", ".join(metrics["sources"]) or "Not recorded", styles["Small"])],
        ["ATT&CK references", _paragraph(", ".join(metrics["techniques"]) or "No ATT&CK techniques mapped", styles["Small"])],
    ]
    table = Table(rows, colWidths=[42 * mm, 212 * mm])
    table.setStyle(_key_value_style())
    return table


def _operational_assessment(metrics: dict[str, Any]) -> str:
    if metrics["incidents"]:
        return f"This analysis produced {metrics['alerts']} alert(s) and correlated them into {metrics['incidents']} incident case(s). The highest recorded severity is {metrics['highest_severity']}. Findings remain evidence-led and require an authorized analyst to validate business context, determine disposition and approve any containment or remediation action."
    if metrics["alerts"]:
        return f"This analysis produced {metrics['alerts']} alert(s), but no correlated incident case was created. The findings should be triaged against the evidence and local business context before closure or escalation."
    return "No alert or incident was produced for this analysis. This result means the available telemetry did not match the enabled governed detections; it is not proof that the environment is free of malicious activity."


def _alert_table(alerts_df: pd.DataFrame, styles) -> LongTable:
    rows: list[list[Any]] = [["Detection", "Severity", "Source", "Risk", "Confidence", "ATT&CK", "Evidence trace"]]
    for _, row in alerts_df.iterrows():
        supporting = row.get("supporting_event_ids", row.get("supporting_event_uuids"))
        rows.append([_paragraph(row.get("detection_name"), styles["Small"]), _paragraph(row.get("severity"), styles["Small"]), _paragraph(row.get("source_ip"), styles["Small"]), _paragraph(_format_number(row.get("risk_score")), styles["Small"]), _paragraph(_format_number(row.get("confidence")), styles["Small"]), _paragraph(row.get("mitre_technique_id"), styles["Small"]), _paragraph(_evidence_summary(supporting), styles["Small"])])
    table = LongTable(rows, repeatRows=1, colWidths=[55 * mm, 21 * mm, 31 * mm, 16 * mm, 21 * mm, 24 * mm, 86 * mm])
    table.setStyle(_table_style(compact=True))
    commands: list[tuple[Any, ...]] = []
    for index, (_, row) in enumerate(alerts_df.iterrows(), start=1):
        color = SEVERITY_COLORS.get(_display_value(row.get("severity"), "unknown").lower(), MUTED)
        commands.extend([("TEXTCOLOR", (1, index), (1, index), color), ("FONTNAME", (1, index), (1, index), BOLD_FONT)])
    table.setStyle(TableStyle(commands))
    return table


def _incident_register(incidents_df: pd.DataFrame, styles) -> LongTable:
    rows: list[list[Any]] = [["Incident", "Severity", "Priority", "Risk", "Status", "Assignee", "ATT&CK path"]]
    for _, row in incidents_df.iterrows():
        title = row.get("incident_name", row.get("title", "Incident"))
        rows.append([_paragraph(title, styles["Small"]), _paragraph(row.get("severity"), styles["Small"]), _paragraph(row.get("priority"), styles["Small"]), _paragraph(_format_number(row.get("risk_score")), styles["Small"]), _paragraph(_status_label(row.get("status")), styles["Small"]), _paragraph(row.get("assignee"), styles["Small"], "Unassigned"), _paragraph(row.get("stage_progression"), styles["Small"], "No ordered path")])
    table = LongTable(rows, repeatRows=1, colWidths=[59 * mm, 22 * mm, 18 * mm, 16 * mm, 27 * mm, 30 * mm, 82 * mm])
    table.setStyle(_table_style(compact=True))
    return table


def _timeline_sort_key(record: dict[str, Any]) -> tuple[int, str]:
    value = record.get("timestamp")
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(parsed):
        return (1, _display_value(value, ""))
    return (0, parsed.isoformat())


def build_case_timeline_records(details: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only events/alerts that are evidence-linked to one persisted incident."""
    records: list[dict[str, Any]] = []
    for event in details.get("events") or []:
        records.append({"timestamp": event.get("timestamp"), "type": "Event", "source_ip": event.get("source_ip"), "username": event.get("username"), "description": event.get("normalized_message") or event.get("raw_message") or event.get("event_type") or "Supporting event", "event_uuid": event.get("event_uuid")})
    for alert in details.get("alerts") or []:
        severity = _display_value(alert.get("severity"), "Alert")
        description = _display_value(alert.get("description"), "Detection alert")
        records.append({"timestamp": alert.get("timestamp"), "type": "Alert", "source_ip": alert.get("source_ip"), "username": alert.get("username"), "description": f"{severity}: {description}", "event_uuid": None})
    return sorted(records, key=_timeline_sort_key)


def additional_analysis_event_records(events_df: pd.DataFrame, incident_details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return analysis events that are not linked to any persisted incident evidence."""
    if events_df.empty:
        return []
    linked_event_uuids = {str(event.get("event_uuid")) for details in incident_details for event in (details.get("events") or []) if event.get("event_uuid")}
    records: list[dict[str, Any]] = []
    for row in events_df.to_dict(orient="records"):
        event_uuid = str(row.get("event_uuid") or "")
        if event_uuid and event_uuid in linked_event_uuids:
            continue
        records.append({"timestamp": row.get("timestamp"), "type": "Event", "source_ip": row.get("source_ip"), "username": row.get("username"), "description": row.get("normalized_message") or row.get("raw_message") or row.get("description") or row.get("event_type") or "Analysis event", "event_uuid": row.get("event_uuid")})
    return sorted(records, key=_timeline_sort_key)


def _timeline_table(records: list[dict[str, Any]], styles) -> LongTable:
    rows: list[list[Any]] = [["Timestamp (UTC)", "Type", "Source", "Username", "Description"]]
    for record in records:
        rows.append([_paragraph(_format_timestamp(record.get("timestamp")), styles["Tiny"]), _paragraph(record.get("type"), styles["Tiny"]), _paragraph(record.get("source_ip"), styles["Tiny"]), _paragraph(record.get("username"), styles["Tiny"], "No associated user"), _paragraph(record.get("description"), styles["Tiny"])])
    table = LongTable(rows, repeatRows=1, colWidths=[42 * mm, 18 * mm, 29 * mm, 32 * mm, 133 * mm])
    table.setStyle(_table_style(compact=True))
    return table


def _details_by_incident_uuid(incident_details: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for details in incident_details or []:
        incident_uuid = str((details.get("incident") or {}).get("incident_uuid") or "").strip()
        if incident_uuid:
            mapping[incident_uuid] = details
    return mapping


def _incident_overview_table(row: pd.Series, styles) -> Table:
    correlation = f"{_display_value(row.get('correlation_version'), 'Legacy')} / {_display_value(row.get('correlation_id'), 'Not available')}"
    graph = f"Sources: {_display_value(row.get('source_count'), '0')} | Entities: {_display_value(row.get('entity_count'), '0')} | Relationships: {_display_value(row.get('relationship_count'), '0')} | Graph score: {_format_number(row.get('graph_score'), default='0')}"
    rows = [
        ["Incident UUID", _paragraph(_display_value(row.get("incident_uuid"), "Not persisted"), styles["Small"]), "Severity / Priority", _paragraph(f"{_display_value(row.get('severity'))} / {_display_value(row.get('priority'), 'Not set')}", styles["Small"])],
        ["Status / Assignee", _paragraph(f"{_status_label(row.get('status'))} / {_display_value(row.get('assignee'), 'Unassigned')}", styles["Small"]), "Risk / Confidence", _paragraph(f"{_format_number(row.get('risk_score'))} / {_format_number(row.get('confidence'))}", styles["Small"])],
        ["Correlation identity", _paragraph(correlation, styles["Small"]), "Graph evidence", _paragraph(graph, styles["Small"])],
        ["ATT&CK progression", _paragraph(_display_value(row.get("stage_progression"), "No ordered path"), styles["Small"]), "", ""],
    ]
    table = Table(rows, colWidths=[34 * mm, 88 * mm, 34 * mm, 98 * mm], splitByRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("BACKGROUND", (0, 0), (0, -1), SURFACE_ALT),
        ("BACKGROUND", (2, 0), (2, -2), SURFACE_ALT),
        ("FONTNAME", (0, 0), (0, -1), BOLD_FONT),
        ("FONTNAME", (2, 0), (2, -2), BOLD_FONT),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY_LIGHT),
        ("TEXTCOLOR", (2, 0), (2, -2), NAVY_LIGHT),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE),
        ("SPAN", (1, -1), (-1, -1)),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _narrative_callout(title: str, content: Any, styles, default: str, *, accent=TEAL) -> Table:
    body = [Paragraph(_text(title), styles["MetaLabel"]), Spacer(1, 2), _paragraph(content, styles["Callout"], default)]
    table = Table([[body]], colWidths=[254 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SURFACE), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("LINEBEFORE", (0, 0), (0, -1), 3, accent), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    return table


def _case_completeness_table(notes: list[dict[str, Any]], evidence: list[dict[str, Any]], styles) -> Table:
    note_text = f"{len(notes)} recorded" if notes else "None recorded"
    evidence_text = f"{len(evidence)} registered" if evidence else "None registered"
    table = Table(
        [["Analyst notes", _paragraph(note_text, styles["Small"]), "Registered evidence", _paragraph(evidence_text, styles["Small"])]],
        colWidths=[32 * mm, 94 * mm, 38 * mm, 90 * mm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BACKGROUND", (0, 0), (0, 0), SURFACE_ALT),
        ("BACKGROUND", (2, 0), (2, 0), SURFACE_ALT),
        ("FONTNAME", (0, 0), (0, 0), BOLD_FONT),
        ("FONTNAME", (2, 0), (2, 0), BOLD_FONT),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _append_case_notes_and_evidence(story: list[Any], details: dict[str, Any] | None, styles) -> None:
    if details is None:
        story.extend([Paragraph("Case record completeness", styles["SubsectionHeading"]), _narrative_callout("LIMITATION", "Persisted case notes, registered evidence metadata and an incident-linked timeline were unavailable when this report was generated.", styles, "Not available")])
        return
    notes = list(details.get("notes") or [])
    evidence = list(details.get("evidence") or [])
    story.extend([Paragraph("Case completeness", styles["SubsectionHeading"]), _case_completeness_table(notes, evidence, styles)])
    if notes:
        story.append(Paragraph("Analyst notes", styles["SubsectionHeading"]))
        rows: list[list[Any]] = [["Author", "Created (UTC)", "Note"]]
        for note in notes:
            rows.append([_paragraph(note.get("author"), styles["Small"]), _paragraph(_format_timestamp(note.get("created_at")), styles["Small"]), _paragraph(note.get("note"), styles["Small"])])
        table = LongTable(rows, repeatRows=1, colWidths=[34 * mm, 46 * mm, 174 * mm])
        table.setStyle(_table_style(compact=True))
        story.append(table)
    if evidence:
        story.append(Paragraph("Registered evidence", styles["SubsectionHeading"]))
        rows = [["Type", "Source reference", "SHA-256", "Registered by", "Created", "Description"]]
        for item in evidence:
            rows.append([_paragraph(item.get("evidence_type"), styles["Tiny"]), _paragraph(item.get("source_reference"), styles["Tiny"], "Not specified"), _paragraph(item.get("sha256"), styles["Tiny"], "Not supplied"), _paragraph(item.get("registered_by"), styles["Tiny"], "Not recorded"), _paragraph(_format_timestamp(item.get("created_at")), styles["Tiny"]), _paragraph(item.get("description"), styles["Tiny"])])
        table = LongTable(rows, repeatRows=1, colWidths=[30 * mm, 52 * mm, 55 * mm, 24 * mm, 36 * mm, 57 * mm])
        table.setStyle(_table_style(compact=True))
        story.append(table)



def _append_saved_ai_investigations(
    story: list[Any], investigations: list[dict[str, Any]], styles
) -> None:
    """Render persisted, incident-scoped AI responses without invoking a model."""
    story.append(Paragraph("Saved AI investigations", styles["SubsectionHeading"]))
    if not investigations:
        story.append(_paragraph(
            "No completed AI investigation answer was saved for this incident at report generation.",
            styles["Small"],
        ))
        return

    story.append(_paragraph(
        "Up to five most recent completed answers are reproduced from persisted jobs. "
        "AI assessments are advisory, not deterministic detections or approved response actions.",
        styles["Small"],
    ))
    for index, item in enumerate(investigations[:5], start=1):
        response = item.get("response") or {}
        if not isinstance(response, dict):
            continue
        story.extend([
            Spacer(1, 7),
            Paragraph(f"Saved question {index:02d}", styles["SubsectionHeading"]),
            _paragraph(
                f"Asked by {_display_value(item.get('actor'))} | "
                f"Completed {_format_timestamp(item.get('completed_at'))} | "
                f"Job {_display_value(item.get('job_uuid'))} | "
                f"Query {_display_value(item.get('query_uuid'))}",
                styles["Small"],
            ),
            _paragraph(
                f"Response: {_display_value(response.get('status'))} | "
                f"Model: {_display_value(response.get('served_model') or response.get('llm_model'))} | "
                f"Grounding score: {_format_number(response.get('grounding_score'))}",
                styles["Small"],
            ),
            Paragraph("QUESTION", styles["AnswerLabel"]),
            _paragraph(item.get("question"), styles["BodyText"]),
            Spacer(1, 4),
            Paragraph("GROUNDED ANSWER", styles["AnswerLabel"]),
            _paragraph(response.get("assessment"), styles["BodyText"]),
        ])
        assessment_ids = response.get("assessment_citation_ids") or []
        if isinstance(assessment_ids, list) and assessment_ids:
            story.append(_paragraph(
                "Assessment citations: " + ", ".join(str(value) for value in assessment_ids),
                styles["Small"],
            ))

        for title, key in (
            ("Key findings", "key_findings"),
            ("Recommended actions", "recommended_actions"),
        ):
            claims = response.get(key) or []
            if not isinstance(claims, list) or not claims:
                continue
            story.append(Paragraph(title, styles["SubsectionHeading"]))
            for claim in claims:
                if not isinstance(claim, dict):
                    continue
                ids = claim.get("citation_ids") or []
                suffix = (
                    f"&#160;[Citations: {_text(', '.join(str(value) for value in ids))}]"
                    if isinstance(ids, list) and ids else ""
                )
                story.append(Paragraph(
                    f"<bullet>&bull;</bullet>{_text(claim.get('text'), 'Not available')}"
                    f"{suffix}",
                    styles["BulletBody"],
                ))

        techniques = response.get("technique_explanations") or []
        if isinstance(techniques, list) and techniques:
            story.append(Paragraph("Technique explanations", styles["SubsectionHeading"]))
            for technique in techniques:
                if not isinstance(technique, dict):
                    continue
                story.append(_paragraph(
                    f"{_display_value(technique.get('technique_id'))} - "
                    f"{_display_value(technique.get('technique_name'))}",
                    styles["TechniqueHeading"],
                ))
                for label, key in (
                    ("Observed", "observed_evidence"),
                    ("Governed", "governed_explanation"),
                    ("Inference", "analyst_inference"),
                ):
                    if not _is_missing(technique.get(key)):
                        story.append(_paragraph(
                            f"{label}: {_display_value(technique.get(key))}",
                            styles["Small"],
                        ))

        limitations = response.get("limitations") or []
        if isinstance(limitations, list) and limitations:
            story.append(Paragraph("Limitations", styles["SubsectionHeading"]))
            for limitation in limitations:
                story.append(Paragraph(
                    f"<bullet>&bull;</bullet>{_text(limitation)}", styles["BulletBody"]
                ))

        citations = response.get("citations") or []
        if isinstance(citations, list) and citations:
            story.append(Paragraph("Supporting citations", styles["SubsectionHeading"]))
            story.append(_paragraph(
                "Excerpts are shortened and display-normalized for readability. "
                "Citation IDs and source references identify the persisted evidence.",
                styles["Small"],
            ))
            rows: list[list[Any]] = [
                ["Citation ID", "Source type", "Reference", "Source and excerpt"]
            ]
            for citation in citations:
                if not isinstance(citation, dict):
                    continue
                rows.append([
                    _paragraph(citation.get("citation_id"), styles["CitationKey"]),
                    _paragraph(citation.get("source_type"), styles["CitationKey"]),
                    _paragraph(citation.get("source_reference"), styles["CitationKey"], "Not recorded"),
                    _paragraph(
                        f"{_display_value(citation.get('title'))}: "
                        f"{_citation_excerpt(citation.get('snippet'))}",
                        styles["Tiny"],
                    ),
                ])
            if len(rows) > 1:
                table = LongTable(
                    rows, repeatRows=1,
                    colWidths=[35 * mm, 37 * mm, 73 * mm, 109 * mm],
                )
                table.setStyle(_table_style(compact=True))
                story.append(table)


def _recommendations(alerts_df: pd.DataFrame) -> list[str]:
    if not alerts_df.empty and "recommendation" in alerts_df.columns:
        ordered = alerts_df.copy()
        risk_values = ordered["risk_score"] if "risk_score" in ordered.columns else pd.Series(-1, index=ordered.index)
        confidence_values = ordered["confidence"] if "confidence" in ordered.columns else pd.Series(-1, index=ordered.index)
        ordered["_risk_sort"] = pd.to_numeric(risk_values, errors="coerce").fillna(-1)
        ordered["_confidence_sort"] = pd.to_numeric(confidence_values, errors="coerce").fillna(-1)
        ordered = ordered.sort_values(["_risk_sort", "_confidence_sort"], ascending=False, kind="stable")
        recommendations: list[str] = []
        seen: set[str] = set()
        for value in ordered["recommendation"].dropna():
            recommendation = str(value).strip()
            if recommendation and recommendation not in seen:
                recommendations.append(recommendation)
                seen.add(recommendation)
        if recommendations:
            return recommendations
    return ["Validate the suspicious activity against approved administrative and user behavior.", "Review related authentication, endpoint and network evidence.", "Contain confirmed malicious accounts, sessions, hosts or infrastructure.", "Document analyst decisions, evidence hashes and remediation before resolving the case."]


def _response_plan_table(recommendations: list[str], styles) -> LongTable:
    rows: list[list[Any]] = [["Priority", "Recommended action", "Control objective"]]
    count = len(recommendations)
    for index, recommendation in enumerate(recommendations):
        if index == 0:
            priority, objective = "P1 - Immediate", "Validate scope and establish whether containment is required."
        elif index < max(2, count - 1):
            priority, objective = "P2 - Near term", "Reduce exposure and preserve supporting evidence."
        else:
            priority, objective = "P3 - Closure", "Verify remediation, document decisions and retain the audit trail."
        rows.append([_paragraph(priority, styles["Small"]), _paragraph(recommendation, styles["Small"]), _paragraph(objective, styles["Small"])])
    table = LongTable(rows, repeatRows=1, colWidths=[35 * mm, 139 * mm, 80 * mm])
    table.setStyle(_table_style())
    return table


def _append_methodology(story: list[Any], report_id: str, styles) -> None:
    story.extend([PageBreak(), Paragraph("Methodology, boundaries and integrity", styles["SectionHeading"])])
    statements = [
        "Detections are produced by deterministic, governed security rules. Saved AI answers are advisory and do not change detection or incident outcomes.",
        "ATT&CK identifiers here are recorded alert and incident references, not a claim of valid governed rule coverage or attacker attribution. Validate mappings against the rule catalogue before asserting coverage.",
        "Correlation groups alerts by shared entities, time and ordered security stages. Correlation confidence supports prioritization and does not replace analyst judgment.",
        "This report reflects persisted evidence available at generation time. Saved AI answers, when authorized and available, are reproduced without model regeneration. Missing notes, evidence registrations or telemetry sources are stated as limitations rather than inferred.",
        "The download response includes an X-Content-SHA256 digest. Preserve that digest with the report to verify file integrity after transfer.",
        "Recommended actions are advisory. Destructive or production-changing actions require explicit human authorization and auditable execution.",
    ]
    for statement in statements:
        story.append(Paragraph(f"<bullet>&bull;</bullet>{_text(statement)}", styles["BulletBody"]))
    rows = [["Report ID", _paragraph(report_id, styles["Small"])], ["Classification", _paragraph(REPORT_CLASSIFICATION, styles["Small"])], ["Integrity mechanism", _paragraph("SHA-256 digest returned in the HTTP response header", styles["Small"])], ["Detection boundary", _paragraph("Deterministic governed rules; AI is downstream and advisory", styles["Small"])], ["Action boundary", _paragraph("Human approval required for containment and response execution", styles["Small"])]]
    table = Table(rows, colWidths=[48 * mm, 206 * mm])
    table.setStyle(_key_value_style())
    story.append(table)


def generate_incident_report(
    events_df: pd.DataFrame,
    alerts_df: pd.DataFrame,
    incidents_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    output_dir: str = "data/reports",
    *,
    session_uuid: str | None = None,
    analysis_name: str | None = None,
    analyst: str | None = None,
    incident_details: list[dict[str, Any]] | None = None,
    ai_investigations: dict[str, list[dict[str, Any]]] | None = None,
) -> str:
    """Generate a professional, pagination-safe incident report from persisted evidence."""
    _register_report_fonts()
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC)
    timestamp = generated_at.strftime("%Y%m%d_%H%M%S")
    report_id = _report_identifier(session_uuid, generated_at)
    report_path = Path(output_dir) / f"threatlens_incident_report_{timestamp}_{uuid4().hex[:12]}.pdf"
    document = SimpleDocTemplate(
        str(report_path), pagesize=landscape(A4), leftMargin=21.5 * mm, rightMargin=21.5 * mm,
        topMargin=18 * mm, bottomMargin=16 * mm, title=f"{PROJECT_NAME} {REPORT_TITLE}",
        author=analyst or PROJECT_NAME, subject=f"Evidence-backed incident investigation report for {analysis_name or 'analysis session'}",
        keywords="ThreatLens AI, incident response, SOC, DFIR, evidence, MITRE ATT&CK", pageCompression=1,
    )
    styles = _build_styles()
    metrics = _report_metrics(events_df, alerts_df, incidents_df)
    details_map = _details_by_incident_uuid(incident_details)
    story: list[Any] = [
        KeepTogether([
            _title_panel(analysis_name, report_id, styles),
            Spacer(1, 8),
            _metadata_grid(session_uuid, analyst, generated_at, metrics, styles),
        ]),
        Spacer(1, 11),
        Paragraph("Executive overview", styles["SectionHeading"]), _metric_cards(metrics, styles), Spacer(1, 8),
        _narrative_callout("OPERATIONAL ASSESSMENT", _operational_assessment(metrics), styles, "No assessment available"), Spacer(1, 8),
        _overview_table(metrics, styles), PageBreak(), Paragraph("Findings register", styles["SectionHeading"]),
    ]
    if alerts_df.empty:
        story.append(_narrative_callout("ALERT REGISTER", "No alert was generated by the enabled governed detections for this analysis.", styles, "No alerts"))
    else:
        story.extend([_paragraph("Detection alerts are listed with their observed risk, confidence, recorded ATT&CK reference and linked-event trace.", styles["BodyText"]), Spacer(1, 6), _alert_table(alerts_df, styles)])
    story.extend([Spacer(1, 10), Paragraph("Incident register", styles["SectionHeading"])])
    if incidents_df.empty:
        story.append(_narrative_callout("CORRELATION RESULT", "No incident case was produced by correlation for this analysis.", styles, "No incidents"))
    else:
        story.append(_incident_register(incidents_df, styles))

    if not incidents_df.empty:
        for incident_index, (_, row) in enumerate(incidents_df.iterrows(), start=1):
            incident_uuid = _display_value(row.get("incident_uuid"), "")
            title = row.get("incident_name", row.get("title", "Incident"))
            severity = _display_value(row.get("severity"), "Unknown")
            severity_accent = SEVERITY_COLORS.get(severity.lower(), MUTED)
            story.extend([
                PageBreak(), Paragraph(f"INCIDENT {incident_index:02d}", styles["Eyebrow"]),
                Paragraph(_text(title, "Incident"), styles["SectionHeading"]),
                _narrative_callout("CURRENT CASE POSTURE", f"{severity} severity | {_display_value(row.get('priority'), 'Priority not set')} | Risk {_format_number(row.get('risk_score'))} | {_status_label(row.get('status'))}", styles, "Case posture not available", accent=severity_accent),
                Spacer(1, 5), _incident_overview_table(row, styles), Spacer(1, 5),
                _narrative_callout("INCIDENT SUMMARY", row.get("summary"), styles, "No incident summary is available."), Spacer(1, 4),
                _narrative_callout("CORRELATION ANALYSIS", row.get("storyline"), styles, "No advanced correlation storyline is available."),
            ])
            details = details_map.get(incident_uuid)
            _append_case_notes_and_evidence(story, details, styles)
            if ai_investigations is not None:
                _append_saved_ai_investigations(
                    story, ai_investigations.get(incident_uuid, []), styles
                )
            if details is not None:
                story.append(Paragraph("Evidence timeline", styles["SubsectionHeading"]))
                case_records = build_case_timeline_records(details)
                if case_records:
                    story.append(_timeline_table(case_records, styles))
                else:
                    story.append(_narrative_callout("TIMELINE STATUS", "No incident-linked timeline evidence is available.", styles, "No timeline"))
    else:
        story.extend([PageBreak(), Paragraph("Analysis timeline", styles["SectionHeading"])])
        if timeline_df.empty:
            story.append(_narrative_callout("TIMELINE STATUS", "No timeline is available for this analysis.", styles, "No timeline"))
        else:
            story.append(_timeline_table([dict(row) for _, row in timeline_df.iterrows()], styles))

    if incident_details:
        additional = additional_analysis_event_records(events_df, incident_details)
        if additional:
            story.extend([Spacer(1, 10), Paragraph("Additional analysis events", styles["SectionHeading"]), Paragraph("These records belong to the same analysis session but are explicitly separated because they are not linked as supporting evidence for the correlated incidents above.", styles["BodyText"]), Spacer(1, 6), _timeline_table(additional, styles)])

    story.append(PageBreak())
    recommendation_flowables = [
        Paragraph("Response and governance", styles["SectionHeading"]),
        Paragraph("The following actions are derived from the governed detection recommendations. Sequence and scope must be confirmed by an authorized responder.", styles["BodyText"]),
        Spacer(1, 6),
    ]
    story.append(KeepTogether(recommendation_flowables))
    story.extend([
        _response_plan_table(_recommendations(alerts_df), styles), Spacer(1, 8),
        _narrative_callout("HUMAN AUTHORIZATION BOUNDARY", "ThreatLens records approval-gated response activity. This report does not execute endpoint, identity, network or firewall changes. Production actions require explicit human approval and auditable execution evidence.", styles, "Human approval required"),
    ])
    _append_methodology(story, report_id, styles)
    document.build(story, onFirstPage=_draw_page, onLaterPages=_draw_page)
    return str(report_path)
