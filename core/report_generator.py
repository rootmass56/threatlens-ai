from __future__ import annotations

import ast
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
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
_MISSING_TEXT_VALUES = {"", "<na>", "nan", "nat", "none", "null"}


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


def _paragraph(
    value: Any,
    style: ParagraphStyle,
    default: str = "Not available",
) -> Paragraph:
    return Paragraph(_text(value, default), style)


def _status_label(value: Any) -> str:
    return _display_value(value, "Open").replace("_", " ").title()


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


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2438")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5F7")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def _draw_page(canvas, document) -> None:
    canvas.saveState()
    width, height = document.pagesize
    canvas.setStrokeColor(colors.HexColor("#1477A8"))
    canvas.setLineWidth(0.8)
    canvas.rect(10 * mm, 10 * mm, width - 20 * mm, height - 20 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#425466"))
    canvas.drawString(15 * mm, 7 * mm, f"{PROJECT_NAME} | Incident Investigation Report")
    canvas.drawRightString(width - 15 * mm, 7 * mm, f"Page {document.page}")
    canvas.restoreState()


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
        records.append(
            {
                "timestamp": event.get("timestamp"),
                "type": "Event",
                "source_ip": event.get("source_ip"),
                "username": event.get("username"),
                "description": (
                    event.get("normalized_message")
                    or event.get("raw_message")
                    or event.get("event_type")
                    or "Supporting event"
                ),
                "event_uuid": event.get("event_uuid"),
            }
        )
    for alert in details.get("alerts") or []:
        severity = _display_value(alert.get("severity"), "Alert")
        description = _display_value(alert.get("description"), "Detection alert")
        records.append(
            {
                "timestamp": alert.get("timestamp"),
                "type": "Alert",
                "source_ip": alert.get("source_ip"),
                "username": alert.get("username"),
                "description": f"{severity}: {description}",
                "event_uuid": None,
            }
        )
    return sorted(records, key=_timeline_sort_key)


def additional_analysis_event_records(
    events_df: pd.DataFrame,
    incident_details: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return analysis events that are not linked to any persisted incident evidence."""

    if events_df.empty:
        return []
    linked_event_uuids = {
        str(event.get("event_uuid"))
        for details in incident_details
        for event in (details.get("events") or [])
        if event.get("event_uuid")
    }
    records: list[dict[str, Any]] = []
    for row in events_df.to_dict(orient="records"):
        event_uuid = str(row.get("event_uuid") or "")
        if event_uuid and event_uuid in linked_event_uuids:
            continue
        records.append(
            {
                "timestamp": row.get("timestamp"),
                "type": "Event",
                "source_ip": row.get("source_ip"),
                "username": row.get("username"),
                "description": (
                    row.get("normalized_message")
                    or row.get("raw_message")
                    or row.get("description")
                    or row.get("event_type")
                    or "Analysis event"
                ),
                "event_uuid": row.get("event_uuid"),
            }
        )
    return sorted(records, key=_timeline_sort_key)


def _timeline_table(records: list[dict[str, Any]], small: ParagraphStyle) -> LongTable:
    rows = [["Timestamp", "Type", "Source", "Username", "Description"]]
    for record in records:
        rows.append(
            [
                _paragraph(record.get("timestamp"), small),
                _paragraph(record.get("type"), small),
                _paragraph(record.get("source_ip"), small),
                _paragraph(record.get("username"), small, "No associated user"),
                _paragraph(record.get("description"), small),
            ]
        )
    table = LongTable(
        rows,
        repeatRows=1,
        colWidths=[40 * mm, 20 * mm, 30 * mm, 34 * mm, 120 * mm],
    )
    table.setStyle(_table_style())
    return table


def _details_by_incident_uuid(
    incident_details: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for details in incident_details or []:
        incident_uuid = str((details.get("incident") or {}).get("incident_uuid") or "").strip()
        if incident_uuid:
            mapping[incident_uuid] = details
    return mapping


def _append_case_notes_and_evidence(
    story: list[Any],
    details: dict[str, Any] | None,
    styles,
    small: ParagraphStyle,
) -> None:
    if details is None:
        story.append(
            Paragraph(
                "Persisted case notes/evidence were unavailable while this report was generated.",
                styles["BodyText"],
            )
        )
        return

    story.append(Paragraph("Investigation Notes", styles["Heading4"]))
    notes = list(details.get("notes") or [])
    if not notes:
        story.append(
            Paragraph("No analyst notes are registered for this incident.", styles["BodyText"])
        )
    else:
        note_rows = [["Author", "Created (UTC)", "Note"]]
        for note in notes:
            note_rows.append(
                [
                    _paragraph(note.get("author"), small),
                    _paragraph(note.get("created_at"), small),
                    _paragraph(note.get("note"), small),
                ]
            )
        note_table = LongTable(
            note_rows,
            repeatRows=1,
            colWidths=[35 * mm, 48 * mm, 157 * mm],
        )
        note_table.setStyle(_table_style())
        story.append(note_table)

    story.extend([Spacer(1, 6), Paragraph("Registered Evidence", styles["Heading4"])])
    evidence = list(details.get("evidence") or [])
    if not evidence:
        story.append(
            Paragraph("No evidence metadata is registered for this incident.", styles["BodyText"])
        )
    else:
        evidence_rows = [["Type", "Source", "SHA-256", "Registered by", "Created", "Description"]]
        for item in evidence:
            evidence_rows.append(
                [
                    _paragraph(item.get("evidence_type"), small),
                    _paragraph(item.get("source_reference"), small, "Not specified"),
                    _paragraph(item.get("sha256"), small, "Not supplied"),
                    _paragraph(item.get("registered_by"), small, "Not recorded"),
                    _paragraph(item.get("created_at"), small),
                    _paragraph(item.get("description"), small),
                ]
            )
        evidence_table = LongTable(
            evidence_rows,
            repeatRows=1,
            colWidths=[22 * mm, 42 * mm, 72 * mm, 30 * mm, 42 * mm, 56 * mm],
        )
        evidence_table.setStyle(_table_style())
        story.append(evidence_table)


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
) -> str:
    """Generate a pagination-safe technical incident report from persisted case evidence."""

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    unique_suffix = uuid4().hex[:12]
    report_path = Path(output_dir) / f"threatlens_incident_report_{timestamp}_{unique_suffix}.pdf"
    document = SimpleDocTemplate(
        str(report_path),
        pagesize=landscape(A4),
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"{PROJECT_NAME} Incident Report",
        author=analyst or PROJECT_NAME,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CenterTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0B2438"),
        )
    )
    small = ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    )
    small_inverse = ParagraphStyle(
        name="SmallInverse",
        parent=small,
        textColor=colors.white,
    )
    details_map = _details_by_incident_uuid(incident_details)
    story: list[Any] = [
        Paragraph(f"{PROJECT_NAME} Incident Investigation Report", styles["CenterTitle"]),
        Spacer(1, 8),
    ]

    metadata = [
        ["Analysis", _paragraph(analysis_name, small, "Current Analysis")],
        ["Session UUID", _paragraph(session_uuid, small)],
        ["Analyst", _paragraph(analyst, small, "Not specified")],
        ["Generated (UTC)", _paragraph(datetime.now(UTC).isoformat(), small)],
    ]
    metadata_table = Table(metadata, colWidths=[35 * mm, 180 * mm])
    metadata_table.setStyle(_table_style())
    story.extend([metadata_table, Spacer(1, 12)])

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary = (
        f"The analysis processed {len(events_df)} normalized security events, generated "
        f"{len(alerts_df)} alerts and correlated them into {len(incidents_df)} incident case(s). "
        "All detections are produced by deterministic security logic; ATT&CK mappings are "
        "evidence-supported governed ATT&CK mappings; the AI assistant is not used "
        "for detection."
    )
    story.extend([_paragraph(summary, styles["BodyText"]), Spacer(1, 10)])
    story.append(Paragraph("Alert Summary", styles["Heading2"]))
    if alerts_df.empty:
        story.append(Paragraph("No alerts were detected.", styles["BodyText"]))
    else:
        alert_rows = [
            ["Detection", "Severity", "Source", "Risk", "Confidence", "ATT&CK", "Evidence"]
        ]
        for _, row in alerts_df.iterrows():
            supporting = row.get("supporting_event_ids", row.get("supporting_event_uuids"))
            alert_rows.append(
                [
                    _paragraph(row.get("detection_name"), small),
                    _paragraph(row.get("severity"), small),
                    _paragraph(row.get("source_ip"), small),
                    _paragraph(row.get("risk_score"), small),
                    _paragraph(row.get("confidence"), small),
                    _paragraph(row.get("mitre_technique_id"), small),
                    _paragraph(_evidence_summary(supporting), small),
                ]
            )
        table = LongTable(
            alert_rows,
            repeatRows=1,
            colWidths=[48 * mm, 23 * mm, 32 * mm, 16 * mm, 22 * mm, 25 * mm, 75 * mm],
        )
        table.setStyle(_table_style())
        story.append(table)

    story.extend([Spacer(1, 12), Paragraph("Correlated Incidents", styles["Heading2"])])
    if incidents_df.empty:
        story.append(Paragraph("No incidents were created.", styles["BodyText"]))
    else:
        for _, row in incidents_df.iterrows():
            incident_uuid = _display_value(row.get("incident_uuid"), "")
            title = row.get("incident_name", row.get("title", "Incident"))
            story.append(Paragraph(_text(title, "Incident"), styles["Heading3"]))
            incident_rows = [
                ["Incident UUID", _paragraph(incident_uuid, small_inverse, "Not persisted")],
                [
                    "Correlation",
                    _paragraph(
                        f"{_display_value(row.get('correlation_version'), 'Legacy')} / "
                        f"{_display_value(row.get('correlation_id'), 'Not available')}",
                        small,
                    ),
                ],
                [
                    "Graph Evidence",
                    _paragraph(
                        f"Sources: {_display_value(row.get('source_count'), '0')} | "
                        f"Entities: {_display_value(row.get('entity_count'), '0')} | "
                        f"Relationships: {_display_value(row.get('relationship_count'), '0')} | "
                        f"Graph score: {_display_value(row.get('graph_score'), '0')}",
                        small,
                    ),
                ],
                [
                    "ATT&CK Path",
                    _paragraph(row.get("stage_progression"), small, "No ordered stage path"),
                ],
                [
                    "Severity / Priority",
                    _paragraph(
                        f"{_display_value(row.get('severity'))} / "
                        f"{_display_value(row.get('priority'), 'Not set')}",
                        small,
                    ),
                ],
                [
                    "Risk / Confidence",
                    _paragraph(
                        f"{_display_value(row.get('risk_score'))} / "
                        f"{_display_value(row.get('confidence'))}",
                        small,
                    ),
                ],
                [
                    "Status / Assignee",
                    _paragraph(
                        f"{_status_label(row.get('status'))} / "
                        f"{_display_value(row.get('assignee'), 'Unassigned')}",
                        small,
                    ),
                ],
                ["Summary", _paragraph(row.get("summary"), small)],
                [
                    "Correlation Storyline",
                    _paragraph(row.get("storyline"), small, "No advanced storyline available"),
                ],
            ]
            incident_table = Table(incident_rows, colWidths=[40 * mm, 200 * mm])
            incident_table.setStyle(_table_style())
            story.extend([incident_table, Spacer(1, 6)])
            _append_case_notes_and_evidence(
                story,
                details_map.get(incident_uuid),
                styles,
                small,
            )
            story.append(Spacer(1, 10))

    if incident_details:
        story.extend([PageBreak(), Paragraph("Incident Evidence Timelines", styles["Heading2"])])
        for details in incident_details:
            incident = details.get("incident") or {}
            story.append(
                Paragraph(
                    _text(incident.get("incident_name") or incident.get("title"), "Incident"),
                    styles["Heading3"],
                )
            )
            case_records = build_case_timeline_records(details)
            if case_records:
                story.append(_timeline_table(case_records, small))
            else:
                story.append(
                    Paragraph(
                        "No incident-linked timeline evidence is available.", styles["BodyText"]
                    )
                )
            story.append(Spacer(1, 8))

        additional = additional_analysis_event_records(events_df, incident_details)
        if additional:
            story.extend(
                [
                    Spacer(1, 6),
                    Paragraph(
                        "Additional Analysis Events (not linked to a correlated incident)",
                        styles["Heading2"],
                    ),
                    Paragraph(
                        "These events belong to the same analysis session but are explicitly "
                        "separated because they are not supporting evidence for the correlated "
                        "incidents above.",
                        styles["BodyText"],
                    ),
                    Spacer(1, 6),
                    _timeline_table(additional, small),
                ]
            )
    else:
        story.extend([PageBreak(), Paragraph("Analysis Timeline", styles["Heading2"])])
        if timeline_df.empty:
            story.append(Paragraph("No timeline is available.", styles["BodyText"]))
        else:
            generic_records = [dict(row) for _, row in timeline_df.iterrows()]
            story.append(_timeline_table(generic_records, small))

    recommendations = []
    if not alerts_df.empty and "recommendation" in alerts_df.columns:
        recommendations = sorted(
            {
                str(value).strip()
                for value in alerts_df["recommendation"].dropna()
                if str(value).strip()
            }
        )
    if not recommendations:
        recommendations = [
            "Validate the suspicious activity against approved administrative and user behavior.",
            "Review related authentication, endpoint and network evidence.",
            "Contain confirmed malicious accounts, sessions, hosts or infrastructure.",
            "Document analyst decisions, evidence hashes and remediation before "
            "resolving the case.",
        ]
    recommendation_flowables = [
        Spacer(1, 12),
        Paragraph("Recommended Response Actions", styles["Heading2"]),
    ]
    for index, recommendation in enumerate(recommendations, start=1):
        recommendation_flowables.append(
            Paragraph(f"{index}. {_text(recommendation)}", styles["BodyText"])
        )
    story.append(KeepTogether(recommendation_flowables))

    document.build(story, onFirstPage=_draw_page, onLaterPages=_draw_page)
    return str(report_path)
