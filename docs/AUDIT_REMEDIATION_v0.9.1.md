# ThreatLens AI v0.9.1 Audit Remediation Record

This document maps the independent full-project v0.9.0 ZIP audit findings to concrete v0.9.1 controls.

## Closed findings

### Release manifest integrity

A deterministic release inventory now hashes every releasable file (excluding the manifest itself and explicitly documented runtime material). `scripts.verify_release_manifest` fails on missing, extra, size-changed or hash-changed release files.

### Governed navigation RBAC

Navigation policy is separated from Streamlit rendering so it is testable without UI-runtime coupling. All six roles are included in the governed matrix.

### Six-role behavioral acceptance

The API security suite now creates/authenticates all six roles and verifies exact permission manifests plus representative positive/negative operations.

### JWT example-secret hazard

`THREATLENS_JWT_SECRET` is blank in `.env.example`; known placeholder values are rejected by configuration and rotated by bootstrap.

### Streamlit/API source metadata

`ThreatLensApiClient` serializes per-source `connector_id` and option dictionaries. FastAPI validates exactly one metadata record per uploaded file, only registered connectors, and only the currently supported `analysis_year` option with a bounded year range.

### Upload/UI contract alignment

Streamlit reads canonical server limits through `/api/v1/system/security`; `.ndjson` support now matches connector metadata; remote result rendering uses response statistics rather than local-only pipeline properties.

### TestClient backend warning

The development environment pins `httpx2==2.7.0`, matching the Starlette 1.3 TestClient documentation. The exact Windows dependency gate confirms the installed version.

## No architecture regression

No deterministic detection, ATT&CK, correlation, attack-graph or database schema logic was replaced by generative AI. `rag/` remains a placeholder until v0.10.
