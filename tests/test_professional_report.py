from __future__ import annotations

from pathlib import Path

import pandas as pd
from pypdf import PdfReader

from core.report_generator import _recommendations, _report_metrics, generate_incident_report


def _report_frames() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    events = pd.DataFrame(
        [
            {
                "event_uuid": "event-1",
                "timestamp": "2026-09-20T01:00:00Z",
                "connector_id": "windows_security",
                "source_ip": "203.0.113.77",
                "username": "LAB\\analyst",
                "normalized_message": "Account logon failed <script>alert(1)</script>",
            },
            {
                "event_uuid": "event-2",
                "timestamp": "2026-09-20T01:05:00Z",
                "connector_id": "windows_sysmon",
                "source_ip": "203.0.113.77",
                "username": "LAB\\analyst",
                "normalized_message": "Encoded PowerShell execution observed",
            },
        ]
    )
    alerts = pd.DataFrame(
        [
            {
                "timestamp": "2026-09-20T01:05:00Z",
                "detection_name": "windows_encoded_powershell",
                "severity": "Critical",
                "source_ip": "203.0.113.77",
                "username": "LAB\\analyst",
                "risk_score": 100,
                "confidence": 0.96,
                "mitre_technique_id": "T1059.001",
                "supporting_event_uuids": ["event-1", "event-2"],
                "description": "Encoded PowerShell execution observed",
                "recommendation": "Inspect the command, parent process and script block logs.",
            }
        ]
    )
    incidents = pd.DataFrame(
        [
            {
                "incident_uuid": "incident-1",
                "incident_name": "Credential Access with Suspicious Execution",
                "severity": "Critical",
                "priority": "P1",
                "risk_score": 100,
                "confidence": 0.94,
                "status": "investigating",
                "assignee": "senior_analyst",
                "correlation_version": "0.8.0",
                "correlation_id": "correlation-1",
                "source_count": 2,
                "entity_count": 5,
                "relationship_count": 4,
                "graph_score": 0.91,
                "stage_progression": "Credential Access -> Execution",
                "summary": "One evidence-backed incident was correlated across two sources.",
                "storyline": "Windows Security and Sysmon evidence share the same user and source.",
            }
        ]
    )
    timeline = pd.DataFrame(
        [
            {
                "timestamp": "2026-09-20T01:00:00Z",
                "type": "Event",
                "source_ip": "203.0.113.77",
                "username": "LAB\\analyst",
                "description": "Account logon failed",
            }
        ]
    )
    return events, alerts, incidents, timeline


def test_report_metrics_are_evidence_derived() -> None:
    events, alerts, incidents, _ = _report_frames()

    metrics = _report_metrics(events, alerts, incidents)

    assert metrics["events"] == 2
    assert metrics["alerts"] == 1
    assert metrics["incidents"] == 1
    assert metrics["source_count"] == 2
    assert metrics["sources"] == ["windows_security", "windows_sysmon"]
    assert metrics["highest_severity"] == "Critical"
    assert metrics["max_risk"] == 100
    assert metrics["average_confidence"] == 0.96
    assert metrics["techniques"] == ["T1059.001"]
    assert metrics["status_counts"] == {"Investigating": 1}
    assert metrics["window_start"] == "2026-09-20 01:00:00 UTC"
    assert metrics["window_end"] == "2026-09-20 01:05:00 UTC"


def test_response_recommendations_follow_observed_risk() -> None:
    alerts = pd.DataFrame(
        [
            {"risk_score": 20, "confidence": 0.9, "recommendation": "Review low-risk activity."},
            {"risk_score": 100, "confidence": 0.8, "recommendation": "Contain critical activity."},
            {"risk_score": 70, "confidence": 0.9, "recommendation": "Investigate high-risk activity."},
            {"risk_score": 100, "confidence": 0.7, "recommendation": "Contain critical activity."},
        ]
    )

    assert _recommendations(alerts) == [
        "Contain critical activity.",
        "Investigate high-risk activity.",
        "Review low-risk activity.",
    ]


def test_professional_report_handles_persisted_case_evidence(tmp_path: Path) -> None:
    events, alerts, incidents, timeline = _report_frames()
    details = [
        {
            "incident": incidents.iloc[0].to_dict(),
            "alerts": alerts.to_dict(orient="records"),
            "events": events.to_dict(orient="records"),
            "notes": [
                {
                    "author": "senior_analyst",
                    "created_at": "2026-09-20T01:10:00Z",
                    "note": "Validated evidence; response remains approval-gated.",
                }
            ],
            "evidence": [
                {
                    "evidence_type": "telemetry_bundle",
                    "source_reference": "case://incident-1",
                    "sha256": "a" * 64,
                    "registered_by": "senior_analyst",
                    "created_at": "2026-09-20T01:11:00Z",
                    "description": "Normalized evidence bundle.",
                }
            ],
        }
    ]

    report_path = Path(
        generate_incident_report(
            events,
            alerts,
            incidents,
            timeline,
            output_dir=str(tmp_path),
            session_uuid="93aa1e45-480d-4dbb-aae1-e4fd12db3c15",
            analysis_name="Professional report regression",
            analyst="pytest",
            incident_details=details,
        )
    )

    payload = report_path.read_bytes()
    page_count = payload.count(b"/Type /Page") - payload.count(b"/Type /Pages")
    assert payload.startswith(b"%PDF")
    assert len(payload) > 8_000
    assert 5 <= page_count <= 6
    assert b"ThreatLens AI Incident Investigation Report" in payload
    assert b"Evidence-backed incident investigation report" in payload
    assert b"MITRE ATT&CK" in payload
    reader = PdfReader(report_path)
    font_subtypes = {
        str(font.get_object().get("/Subtype"))
        for page in reader.pages
        for font in (page["/Resources"].get("/Font") or {}).values()
    }
    assert "/TrueType" in font_subtypes


def test_professional_report_handles_empty_analysis(tmp_path: Path) -> None:
    empty = pd.DataFrame()

    report_path = Path(
        generate_incident_report(
            empty,
            empty,
            empty,
            empty,
            output_dir=str(tmp_path),
            session_uuid="empty-session",
            analysis_name="Empty analysis boundary test",
            analyst="pytest",
        )
    )

    payload = report_path.read_bytes()
    page_count = payload.count(b"/Type /Page") - payload.count(b"/Type /Pages")
    assert payload.startswith(b"%PDF")
    assert len(payload) > 6_000
    assert page_count >= 5
