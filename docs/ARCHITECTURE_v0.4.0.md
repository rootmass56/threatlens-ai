# ThreatLens AI v0.4 Architecture

## Layered design

### Presentation layer

The Streamlit pages render SOC metrics, ingestion controls, current analysis, persistent cases, audit records, rule governance and reports. Pages call only the application service rather than directly managing transactions.

### Application layer

`ThreatLensApplicationService` orchestrates connector execution, deterministic analysis, duplicate handling, database persistence, case management, rule governance and read models.

### Connector layer

A connector implements:

- metadata
- `validate_source()`
- confidence score
- `parse()`
- parser statistics
- common events
- quarantined records

The registry can select an explicit connector or auto-detect the best valid connector.

### Common schema layer

Every connector emits `CommonEvent` objects validated before detection. The schema separates normalized fields, raw evidence, parser metadata and data-quality findings.

### Rule layer

The validator loads YAML with `yaml.safe_load`, applies Pydantic validation, detects duplicates, validates fixtures and blocks path traversal. Only a valid catalog can execute.

### Detection layer

The generic engine supports:

- event matching
- threshold rules
- group-by
- time windows
- distinct counts
- ordered sequences
- evidence collection
- message templates
- rule-based ATT&CK and response metadata

### Analytics layer

Alerts receive explainable risk factors and are correlated through source, host, identity and time context. The result is an incident storyline and timeline.

### Persistence layer

The persistence service stores an analysis in one transaction. Repositories provide read models. Alembic controls schema changes.

## Trust boundary

Untrusted input exists in uploaded telemetry and YAML rule files. Controls include size limits, safe YAML loading, Pydantic schemas, connector validation, quarantine handling, supported operator allowlists, safe AST condition evaluation, regex limits, fixture path containment and transaction rollback.
