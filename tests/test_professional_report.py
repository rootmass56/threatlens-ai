from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
from reportlab.platypus import LongTable, Paragraph
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.routes.reports import _saved_ai_investigations
from core.report_generator import (
    _append_saved_ai_investigations,
    _build_styles,
    _overview_table,
    _recommendations,
    _report_metrics,
    generate_incident_report,
)
from database.base import Base
from database.models import AiInvestigationJobModel, AnalysisSessionModel, IncidentModel


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
    assert _overview_table(metrics, _build_styles())._cellvalues[-1][0] == "ATT&CK references"
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
    assert b"/Subtype /TrueType" in payload
    assert b"/FontFile2" in payload


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


def test_saved_ai_answers_are_incident_scoped_and_bounded(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'ai-report.db').as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        analyses = [
            AnalysisSessionModel(
                session_uuid=f"report-session-{index}",
                name=f"Report session {index}",
                status="completed",
                source_type="linux_auth",
            )
            for index in range(2)
        ]
        session.add_all(analyses)
        session.flush()
        incidents = [
            IncidentModel(
                incident_uuid=f"report-incident-{index}",
                analysis_session_id=analyses[index].id,
                title=f"Incident {index}",
                severity="High",
                risk_score=75,
                summary="Persisted incident.",
            )
            for index in range(2)
        ]
        session.add_all(incidents)
        session.flush()
        started = datetime(2026, 9, 20, tzinfo=UTC)
        for index in range(6):
            session.add(AiInvestigationJobModel(
                job_uuid=f"00000000-0000-4000-8000-{index:012d}",
                incident_id=incidents[0].id,
                actor="analyst",
                question=f"Question {index}",
                question_sha256=f"{index:064x}",
                analysis_mode="standard",
                status="succeeded",
                request_fingerprint=f"{index:064x}",
                result_query_uuid=f"query-{index}",
                result_json={"assessment": f"Answer {index}", "citations": []},
                completed_at=started + timedelta(minutes=index),
            ))
        session.add(AiInvestigationJobModel(
            job_uuid="00000000-0000-4000-8000-000000000006",
            incident_id=incidents[0].id,
            actor="analyst",
            question="Failed question",
            question_sha256="f" * 64,
            analysis_mode="standard",
            status="failed",
            request_fingerprint="f" * 64,
            result_json={},
        ))
        session.add(AiInvestigationJobModel(
            job_uuid="00000000-0000-4000-8000-000000000007",
            incident_id=incidents[1].id,
            actor="other-analyst",
            question="Different analysis question",
            question_sha256="e" * 64,
            analysis_mode="standard",
            status="succeeded",
            request_fingerprint="e" * 64,
            result_json={"assessment": "Different answer"},
            completed_at=started,
        ))
        session.commit()

        saved = _saved_ai_investigations(session, [incidents[0].incident_uuid])
        assert list(saved) == [incidents[0].incident_uuid]
        assert [item["question"] for item in saved[incidents[0].incident_uuid]] == [
            f"Question {index}" for index in (5, 4, 3, 2, 1)
        ]
        assert all(item["response"]["assessment"].startswith("Answer") for item in saved[incidents[0].incident_uuid])


def test_professional_report_renders_saved_ai_answer_and_citations(tmp_path: Path) -> None:
    events, alerts, incidents, timeline = _report_frames()
    question = "What happened on the affected host?"
    assessment = "Observed event evidence supports suspicious execution. " * 100
    saved = {
        "incident-1": [{
            "job_uuid": "saved-job-1",
            "query_uuid": "saved-query-1",
            "actor": "analyst",
            "question": question,
            "completed_at": "2026-09-20T01:10:00Z",
            "response": {
                "status": "answered",
                "assessment": assessment,
                "assessment_citation_ids": ["INC:event-1"],
                "key_findings": [{
                    "text": "Encoded PowerShell was observed.",
                    "citation_ids": ["INC:event-1"],
                }],
                "recommended_actions": [],
                "technique_explanations": [],
                "limitations": ["Business context has not been independently verified."],
                "citations": [{
                    "citation_id": "INC:event-1",
                    "source_type": "incident_event",
                    "source_reference": "event-1",
                    "title": "Windows event",
                    "snippet": "Encoded PowerShell execution observed.",
                }],
                "grounding_score": 0.92,
                "served_model": "qwen3.5:4b",
            },
        }]
    }
    story = []
    _append_saved_ai_investigations(story, saved["incident-1"], _build_styles())
    paragraphs = " ".join(
        item.getPlainText() for item in story if isinstance(item, Paragraph)
    )
    assert question in paragraphs
    assert "Observed event evidence supports suspicious execution." in paragraphs
    assert "Encoded PowerShell was observed." in paragraphs
    assert "Business context has not been independently verified." in paragraphs
    citation_tables = [item for item in story if isinstance(item, LongTable)]
    assert citation_tables
    assert citation_tables[0]._cellvalues[1][0].getPlainText() == "INC:event-1"

    path = Path(generate_incident_report(
        events, alerts, incidents, timeline,
        output_dir=str(tmp_path),
        ai_investigations=saved,
    ))
    assert path.read_bytes().startswith(b"%PDF")
    assert path.stat().st_size > 8_000
