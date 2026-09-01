from datetime import UTC, datetime
from pathlib import Path

import streamlit as st

from app.api_client import ThreatLensApiClient
from app.state import clear_current_analysis, store_analysis_result
from app.upload_limits import streamlit_upload_limit_mb
from core.pipeline import SourceInput

ROOT_DIR = Path(__file__).resolve().parents[2]
SAMPLE_LOG_DIR = ROOT_DIR / "data" / "sample_logs"
LINUX_SAMPLE = SAMPLE_LOG_DIR / "auth_sample.log"
MULTI_SOURCE_SAMPLE_FILES = (
    SAMPLE_LOG_DIR / "windows_security_sample.jsonl",
    SAMPLE_LOG_DIR / "sysmon_sample.jsonl",
    SAMPLE_LOG_DIR / "suricata_eve_sample.jsonl",
    SAMPLE_LOG_DIR / "zeek_conn_sample.log",
    SAMPLE_LOG_DIR / "zeek_dns_sample.log",
)
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_UPLOAD_FILES = 10


def _server_upload_limits(
    application_service: ThreatLensApiClient,
) -> tuple[int, int, int]:
    status = application_service.security_status()
    payload = status.get("upload_limits") or {}
    max_file_bytes = int(payload.get("max_file_bytes") or DEFAULT_MAX_FILE_BYTES)
    max_files = int(payload.get("max_files") or DEFAULT_MAX_UPLOAD_FILES)
    max_batch_bytes = int(payload.get("max_batch_bytes") or max_file_bytes * max_files)
    return max(max_file_bytes, 1), max(max_files, 1), max(max_batch_bytes, 1)


def _validate_uploads(
    sources: list[SourceInput],
    *,
    max_file_bytes: int,
    max_files: int,
    max_batch_bytes: int,
) -> None:
    if not sources:
        raise ValueError("At least one telemetry source is required.")
    if len(sources) > max_files:
        raise ValueError(f"Select no more than {max_files} telemetry files per analysis.")
    total_bytes = 0
    for source in sources:
        content = source.raw_content
        size = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
        if size == 0:
            raise ValueError(f"The source {source.filename or 'unknown'} is empty.")
        if size > max_file_bytes:
            limit_mib = max_file_bytes / (1024 * 1024)
            raise ValueError(
                f"The source {source.filename or 'unknown'} exceeds the "
                f"{limit_mib:.1f} MiB API file limit."
            )
        total_bytes += size
    if total_bytes > max_batch_bytes:
        limit_mib = max_batch_bytes / (1024 * 1024)
        raise ValueError(f"The combined upload exceeds the {limit_mib:.1f} MiB API batch limit.")


def _render_result(result, analysis_name: str, filename: str) -> None:
    store_analysis_result(result, analysis_name=analysis_name, filename=filename)
    if result.was_persisted:
        st.success("Analysis completed and persisted atomically.")
        st.code(result.session_uuid or "", language=None)
    else:
        st.warning("Identical content was already analyzed; no duplicate record was created.")
        st.code(result.duplicate_session_uuid or "", language=None)

    pipeline = result.pipeline
    statistics = pipeline.combined_parser_statistics()
    columns = st.columns(6)
    source_count = int(statistics.get("source_count") or len(pipeline.source_manifest))
    columns[0].metric("Sources", source_count)
    columns[1].metric("Events", pipeline.event_count)
    columns[2].metric("Alerts", pipeline.alert_count)
    columns[3].metric("Incidents", pipeline.incident_count)
    columns[4].metric("Quarantined", pipeline.quarantined_count)
    columns[5].metric(
        "Parse Success",
        f"{float(statistics.get('parse_success_rate') or 0.0) * 100:.1f}%",
    )
    st.caption(
        f"Connectors: {', '.join(pipeline.connector_ids)} | "
        f"Common schema: {statistics.get('schema_version')}"
    )
    if pipeline.source_manifest:
        st.dataframe(list(pipeline.source_manifest), width="stretch", hide_index=True)


def _execute_sources(
    *,
    application_service: ThreatLensApiClient,
    analysis_name: str,
    sources: list[SourceInput],
    actor: str,
    allow_duplicate: bool,
    max_file_bytes: int,
    max_files: int,
    max_batch_bytes: int,
) -> None:
    _validate_uploads(
        sources,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_batch_bytes=max_batch_bytes,
    )
    with st.spinner(
        "Detecting connectors, normalizing heterogeneous telemetry, evaluating rules, "
        "correlating cross-source evidence and persisting the analysis..."
    ):
        result = application_service.analyze_and_persist_sources(
            analysis_name=analysis_name,
            sources=sources,
            actor=actor,
            allow_duplicate=allow_duplicate,
        )
    names = "; ".join(source.filename or "source" for source in sources)
    _render_result(result, analysis_name, names)


def render_upload(application_service: ThreatLensApiClient) -> None:
    st.header("Upload and Analyze")
    st.info(
        "ThreatLens accepts Linux auth.log, Windows Security, Sysmon, Suricata EVE "
        "and Zeek telemetry. Multiple files can be normalized and analyzed as one incident session."
    )
    connector_catalog = application_service.get_connector_catalog()
    connector_options = ["auto", *connector_catalog["connector_id"].tolist()]
    max_file_bytes, max_files, max_batch_bytes = _server_upload_limits(application_service)
    st.caption(
        "API upload boundary: "
        f"{max_files} files maximum, {max_file_bytes / (1024 * 1024):.1f} MiB per file, "
        f"{max_batch_bytes / (1024 * 1024):.1f} MiB per batch."
    )

    form_columns = st.columns(3)
    analysis_name = form_columns[0].text_input(
        "Analysis name",
        value="Multi-Source Security Telemetry Analysis",
    )
    selected_connector = form_columns[1].selectbox(
        "Connector override",
        options=connector_options,
        format_func=lambda value: "Auto-detect per file" if value == "auto" else value,
        help=(
            "A manual override applies to every selected file. Auto-detection is "
            "recommended for mixed batches."
        ),
    )
    analysis_year = form_columns[2].number_input(
        "Year for yearless Linux syslog",
        min_value=2000,
        max_value=2100,
        value=datetime.now(UTC).year,
    )

    widget_limit_mb = streamlit_upload_limit_mb(max_file_bytes)
    st.caption(
        f"Browser upload control may display {widget_limit_mb} MB because Streamlit uses "
        "decimal MB for its transport cap. ThreatLens still enforces the exact "
        f"{max_file_bytes / (1024 * 1024):.1f} MiB API limit "
        f"({max_file_bytes:,} bytes) before submission."
    )
    uploaded_files = st.file_uploader(
        "Upload one or more security telemetry files",
        type=["log", "txt", "json", "jsonl", "ndjson", "csv"],
        accept_multiple_files=True,
        max_upload_size=widget_limit_mb,
        help=(
            "Each file is validated, normalized and represented in the source manifest. "
            "The browser transport cap is rounded up only so it never rejects a file that "
            "is valid under the exact API byte boundary."
        ),
    )
    allow_duplicate = st.checkbox("Allow intentional duplicate ingestion", value=False)
    buttons = st.columns(4)
    analyze_uploaded = buttons[0].button(
        "Analyze Uploaded Batch",
        type="primary",
        width="stretch",
    )
    analyze_linux = buttons[1].button("Analyze Linux Sample", width="stretch")
    analyze_multi = buttons[2].button("Analyze Multi-Source Demo", width="stretch")
    clear = buttons[3].button("Clear Browser Analysis", width="stretch")
    actor = st.session_state.analyst_identity.strip() or "unknown"
    connector_id = None if selected_connector == "auto" else selected_connector

    if uploaded_files:
        st.subheader("Selected Sources")
        rows = []
        for uploaded_file in uploaded_files:
            diagnostics = application_service.get_connector_diagnostics(
                raw_content=uploaded_file.getvalue(),
                filename=uploaded_file.name,
            )
            top = diagnostics.iloc[0] if not diagnostics.empty else None
            rows.append(
                {
                    "filename": uploaded_file.name,
                    "size_bytes": uploaded_file.size,
                    "best_connector": top["connector_id"] if top is not None else "unknown",
                    "confidence": top["confidence"] if top is not None else 0.0,
                    "valid": bool(top["valid"]) if top is not None else False,
                }
            )
        st.dataframe(rows, width="stretch", hide_index=True)

    if analyze_uploaded:
        if not uploaded_files:
            st.error("Select at least one source file first.")
        else:
            try:
                sources = [
                    SourceInput(
                        raw_content=uploaded_file.getvalue(),
                        filename=uploaded_file.name,
                        connector_id=connector_id,
                        options={"analysis_year": int(analysis_year)},
                    )
                    for uploaded_file in uploaded_files
                ]
                _execute_sources(
                    application_service=application_service,
                    analysis_name=analysis_name,
                    sources=sources,
                    actor=actor,
                    allow_duplicate=allow_duplicate,
                    max_file_bytes=max_file_bytes,
                    max_files=max_files,
                    max_batch_bytes=max_batch_bytes,
                )
            except Exception as error:
                st.exception(error)

    if analyze_linux:
        try:
            _execute_sources(
                application_service=application_service,
                analysis_name=analysis_name,
                sources=[
                    SourceInput(
                        raw_content=LINUX_SAMPLE.read_bytes(),
                        filename=LINUX_SAMPLE.name,
                        connector_id="linux_auth",
                        options={"analysis_year": int(analysis_year)},
                    )
                ],
                actor=actor,
                allow_duplicate=allow_duplicate,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_batch_bytes=max_batch_bytes,
            )
        except Exception as error:
            st.exception(error)

    if analyze_multi:
        try:
            _execute_sources(
                application_service=application_service,
                analysis_name=analysis_name.strip() or "ThreatLens Multi-Source Demo",
                sources=[
                    SourceInput(raw_content=path.read_bytes(), filename=path.name)
                    for path in MULTI_SOURCE_SAMPLE_FILES
                ],
                actor=actor,
                allow_duplicate=allow_duplicate,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_batch_bytes=max_batch_bytes,
            )
        except Exception as error:
            st.exception(error)

    if clear:
        clear_current_analysis()
        st.success("Browser state cleared; persistent database records were preserved.")

    st.subheader("Enabled Connector Registry")
    st.dataframe(connector_catalog, width="stretch", hide_index=True)
