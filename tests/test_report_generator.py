from pathlib import Path

from core.pipeline import analyze_linux_auth_log
from core.report_generator import generate_incident_report

SAMPLE_LOG_PATH = Path("data/sample_logs/auth_sample.log")


def test_pdf_report_is_generated(tmp_path):
    pipeline = analyze_linux_auth_log(SAMPLE_LOG_PATH.read_text(encoding="utf-8-sig"))
    path = generate_incident_report(
        pipeline.events_df,
        pipeline.alerts_df,
        pipeline.incidents_df,
        pipeline.timeline_df,
        output_dir=str(tmp_path),
        session_uuid="test-session",
        analysis_name="Automated report test",
        analyst="pytest",
    )
    report = Path(path)
    assert report.exists()
    assert report.stat().st_size > 1000
    assert report.read_bytes().startswith(b"%PDF")
