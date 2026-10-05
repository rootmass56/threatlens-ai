# Changelog

## v0.14.0 — Batch 7 Operational Hardening (Release Candidate)

### Post-v1.0.0 maintenance

- Pin the API image transitive `urllib3` dependency to `2.8.0` and remove build-only pip from the final runtime, eliminating its vendored vulnerable copy reported under `CVE-2026-97687` and `CVE-2026-97689`.
- Expose canonical `detection_id`, `primary_tactic`, and `primary_technique_id` fields in persisted alert API records while retaining the legacy MITRE aliases for compatibility.
- Add regression coverage for the incident-alert contract used by the React case-evidence table.
- Present the repository as a professional portfolio project: streamline the root, adopt the standard `compose.yaml` entrypoint, group historical Compose contracts, demo launchers and release evidence, and refresh the README/navigation without changing the immutable `v1.0.0` tag.
- Refresh the API/worker Python 3.11 base to pinned Debian Trixie with in-image security updates; the reviewed 2026-09-28 API scan moved from 60 HIGH/CRITICAL (5 Critical) to 44 HIGH (0 Critical), with no published fixes for those remaining records.
- Validate temporary demo tunnel origins by hostname, bound STIX indicator parsing, and keep internal import errors out of API responses.
- Default a standalone syslog collector to loopback and align the Trivy review note with the current runtime msgpack pin.
- Prevent durable AI jobs from being orphaned when Redis delivery races a locked database row.
- Preserve worker claim state when API delivery bookkeeping completes concurrently.
- Keep worker-presence heartbeats active during long local-model inference.
- Align supported Standard and Deep utilities with `qwen3.5:4b` and `qwen3.5:9b`.
- Make governed knowledge re-indexing asynchronous and keep status endpoints responsive.
- Normalize operator-facing database-pool metrics and improve report/UI review workflows.
- Keep local Cloudflare Wrangler state out of version control.

### Published project release mapping

- Published the accepted `0.14.0` internal source line through the protected `main` workflow.
- Froze the evidence-first authority model, final documentation, validation evidence and portfolio demonstration contract.
- Retained internal `0.14.0` version identifiers for runtime and compatibility continuity.

- Added structured JSON logging and request correlation for API/worker runtime.
- Added bounded Prometheus-format application metrics and protected operational status view.
- Added optional Prometheus, Grafana, PostgreSQL exporter and Redis exporter Compose profile.
- Added measured HTTP load/concurrency probes with success-rate and percentile latency thresholds.
- Added Alembic revision `b7f1c2d30001` for operational composite indexes.
- Added PostgreSQL statistics/performance audit tooling.
- Added SHA-256-manifested PostgreSQL backup, isolated restore smoke and guarded approved restore scripts.
- Added request-size ceiling, conditional HSTS, COOP/CORP headers, hidden Nginx version and bounded Uvicorn concurrency.
- Hardened application containers with no-new-privileges, dropped capabilities, PID/resource bounds and loopback-only local published ports.
- Added Batch-7 security audit and threat-model documentation.
- Added GitHub Actions CI, CodeQL, secret scanning, dependency audit, container vulnerability scan and immutable GHCR build workflow.
- Added operational runbooks for startup/shutdown, observability, Redis/worker/database/model outages, backup/restore, credential rotation, deployment rollback and platform security incidents.
- Preserved the frozen v0.13.0 deterministic/evidence-first authority model and all Batch-6 SOC capabilities.

## v0.12.0 — Production Web Platform Release Candidate

- Preserve the frozen v0.11.1 deterministic SOC, security, Grounded RAG and adaptive-routing baseline.
- Add a React + Vite production SOC client that consumes only the authenticated FastAPI boundary.
- Add PostgreSQL production persistence with URL normalization, pooling and SQLite retained for local development.
- Add a native pgvector RAG backend while retaining the ThreatLens-owned SQLite vector backend for local development.
- Upgrade the configurable local/default LLM profiles to Qwen3.5:4B Standard and Qwen3.5:9B Deep while retaining Qwen3-Embedding-0.6B (1024 dimensions).
- Add authenticated HTTPS Ollama-compatible inference configuration for remote production model hosting.
- Add Docker, Render and Vercel deployment contracts plus Alembic pre-deployment migration support.
- Add production initialization and frontend verification gates (install/lock, TypeScript, Vite build and npm audit).
- Add psycopg 3.3.4 and pgvector 0.5.0 to the reviewed direct dependency baseline and regenerate the v0.12 source SBOM.
- Preserve the canonical 44-path / 45-operation API contract while moving the production user experience away from Streamlit.
- Migrate every analyst-facing Streamlit workflow into the React console: upload/current/history analysis, incidents/case evidence, graph investigation, audit, detection quality/fixtures, ATT&CK coverage/Navigator, connector diagnostics, reports, RAG administration and security administration.
- Add machine-governed Streamlit-to-React parity policy and fail-fast verifier.
- Add safe v0.11.1 operational-data migration with integrity/schema/revision checks, automatic target backup and explicit preservation of v0.12 users, credentials, roles and token state.
- Harden local Windows RAG defaults to an embedding batch size of 4 and Standard read timeout of 120 seconds after observed CPU-only Ollama embedding-runner stalls at the previous batch size.
- Add a deterministic local UAT launcher that probes a bindable FastAPI port and binds Vite explicitly to 127.0.0.1.
- Expand the v0.12 production-web suite to 25 tests, including feature-parity and guarded operational-data migration coverage; target 270 platform-independent / 271 Windows governed tests.
- Treat this tree as a release candidate until the real Windows dependency/runtime gate, frontend build/audit gate, and deployment smoke tests pass.

## v0.11.1 — Security Closure and Built-in Vector Persistence

- Upgrade `python-multipart` from 0.0.29 to 0.0.32.
- Upgrade Requests from 2.32.5 to 2.34.2.
- Upgrade pytest from 9.0.2 to 9.0.3.
- Remove `chromadb==1.5.9` and all active Chroma runtime imports.
- Add ThreatLens-owned persistent `SQLiteVectorStore` using Python `sqlite3` and deterministic exact cosine ranking.
- Change the default RAG vector backend to `sqlite` and runtime path to `data/rag/vector_store.sqlite3`.
- Require one-time RAG re-indexing when upgrading from the historical Chroma-backed v0.10/v0.11 runtime.
- Harden the remaining Streamlit demo UI as loopback-only, with client error details disabled and CORS/XSRF enabled; public deployment is explicitly deferred to the v0.12 React frontend.
- Add reviewed dependency-security baseline enforcement and explicit rejection of installed ChromaDB.
- Add recursive installed dependency lock and CycloneDX runtime SBOM generation for the supported Windows / CPython 3.11 environment.
- Add immutable source CycloneDX dependency inventory.
- Correct current verification counts, dependency documentation, runtime configuration names, and third-party-data release wording.
- Add 12 governed v0.11.1 security-closure tests; target 245 platform-independent / 246 Windows tests.
- Retain v0.11 adaptive Standard/Deep routing, citation hardening, guarded model fallback and deterministic grounded degradation.

## v0.11.0 — Adaptive Dual-Model AI Runtime

### v0.11 RC3 reliability hardening
- Added deterministic evidence-only degraded mode when local LLM generation cannot complete.
- Added a guarded Deep failure circuit breaker so a prolonged 8B failure does not automatically stack another multi-minute model request.
- Reduced the default Deep read timeout from 900 seconds to 600 seconds based on measured local 8B completion times, while retaining the 1400-token / 8192-context Deep profile.
- Deterministic fallback responses remain subject to exact technique binding, citation authorization, grounding validation, claim conservatism and incident isolation.

- Add deterministic Auto / Standard / Deep Analysis routing without using an LLM as the router.
- Add governed Qwen3:4B Standard and Qwen3:8B Deep model profiles with independent context, output and timeout budgets.
- Preserve the benchmark-validated Deep profile at 8192 context, 1400 output tokens and a 600-second local read timeout.
- Add transparent Deep-to-Standard fallback for Deep model unavailability or invalid Deep generation.
- Regenerate fallback answers through the same incident evidence, governed knowledge, citation-plane and grounding validators.
- Persist requested mode, resolved mode, requested/served model, fallback state, routing score/reasons and generation latency in existing RAG response/audit metadata without a schema migration.
- Add analyst-facing Auto / Standard / Deep controls and runtime metadata to the Case Details AI Assistant.
- Expose both local model profiles in RAG health/administration while keeping Streamlit behind the authenticated FastAPI boundary.
- Add adaptive runtime verification and 28 governed v0.11 routing/fallback/hardening regressions.
- Keep the v0.10 knowledge-index schema/collection compatible; no ATT&CK or Chroma re-index is required solely for v0.11.
- Alembic head remains `d4a7c0e51010`; deterministic analytics and the v0.10 grounding trust boundary remain authoritative.

### v0.11.0 RC hardening

- Added deterministic ATT&CK technique-explanation deduplication.
- Technique-specific governed citations must now bind to the same ATT&CK ID via an official technique record or explicitly mapped detection rule.
- Generic governed policy documents can no longer satisfy a technique-specific knowledge citation plane.
- Internal short prompt aliases (for example `C6`, `C8`, or `C9-C13`) are stripped from analyst-facing prose.
- Added bounded analyst-inference separation for questions that explicitly request fact-versus-inference analysis.
- Added deterministic conservative-language hardening for common credential-theft, lateral-movement, and credential-dumping overclaims.
- Model fallback messages no longer expose local Ollama host, port, raw HTTP, or timeout implementation details.
- Expanded the v0.11 governed regression group from 16 to 28 tests (233 platform-independent / 234 Windows total).


## v0.10.0 advanced RAG hardening

- Add deterministic query planning and exact ATT&CK/rule retrieval alongside semantic Chroma retrieval.
- Fix Enterprise ATT&CK knowledge ingestion to use the real `enterprise-attack` catalog domain.
- Add explicit cross-incident mismatch refusal and pre-model refusal for absent malware/hash/actor facts.
- Add separate incident-evidence and governed-knowledge citation planes for ATT&CK explanations.
- Add structured per-technique explanations, citation alias restoration, and model-output cardinality normalization.
- Add configurable Ollama context/output budgets and hybrid exact-knowledge limits.


## v0.10.0 — Grounded RAG Investigation Assistant

- Add an incident-scoped grounded investigation assistant while preserving deterministic detection, risk, ATT&CK and correlation authority.
- Add governed knowledge loading for ThreatLens security documentation, detection rules and active Enterprise ATT&CK technique records.
- Add deterministic semantic chunk identities, SHA-256 source versioning and hash-based incremental indexing.
- Add ChromaDB persistent vector-store integration with a deterministic in-memory verification backend.
- Add Ollama/Qwen structured generation and Ollama embedding adapters with strict configured-model health checks and graceful unavailability behavior.
- Separate incident evidence from approved reference knowledge and treat both as untrusted prompt data.
- Add prompt-injection/secret-extraction filtering, attribution refusal, citation allowlisting and grounding-status validation.
- Add `rag:query` and `rag:manage` RBAC permissions plus protected RAG health, index, query and history API operations.
- Add a Case Details AI Assistant tab and privileged AI Knowledge Administration page; Streamlit communicates only through the secured FastAPI boundary.
- Persist assistant query/audit metadata with Alembic revision `d4a7c0e51010`.
- Add canonical OpenAPI normalization for equivalent multipart-binary schema dialects; v0.10 exposes 44 paths / 45 operations.
- Expand v0.10 RAG governance to 32 tests; Windows governed matrix is 206 tests total (205 platform-independent + 1 exact runtime pin).
- Pin `chromadb==1.5.9`; default local Ollama models are `qwen3:4b` and `qwen3-embedding:0.6b`.
- Preserve all v0.9.5 deterministic analytics/security/release controls and baselines.

## v0.9.5 — UAT Remediation and Pre-RAG Closure

- Suppress `incident.workflow_updated` audit entries for true no-op workflow requests while preserving exactly one audit entry for real transitions.
- Include persisted investigation notes and registered evidence metadata in incident PDF reports.
- Split report timelines into incident-linked evidence timelines and explicitly labeled additional analysis events that are not linked to correlated incidents.
- Recover evidence registrant attribution from existing audit provenance without a schema migration.
- Remove obsolete `parameters.catalog_version: 0.6.0` metadata from the 12 affected governed rule YAML files; the authoritative governed catalogue remains v0.7.0.
- Correct the protected OpenAPI contract for incident PDF responses to `application/pdf` with a binary schema.
- Preserve the analyst-supplied analysis name when running the built-in multi-source demonstration.
- Make Viewer Case Details genuinely read-only in the Streamlit UI while retaining backend object/permission enforcement.
- Synchronize Case Details selection with current-analysis/sidebar state and clear selected case state when current analysis is cleared.
- Align Streamlit upload widget limits and exact byte checks with the authoritative API upload limit, including evidence registration.
- Replace absolute rule source paths in API/UI output with repository-relative provenance.
- Document the current security posture that access/refresh tokens remain server-session-only; hard browser refresh therefore requires sign-in rather than persisting JWTs to browser localStorage or JavaScript-readable cookies.
- Add 17 governed v0.9.5 UAT-remediation regressions, including persisted multi-source reload fidelity; the Windows release matrix is 174 tests total (173 platform-independent + 1 exact runtime pin).
- Clarify true no-op workflow submissions in the UI so analysts are told that no state or audit record changed.
- Keep the incident-report recommendation heading and actions together to prevent an orphaned final response action on a nearly empty page.
- Explain the Streamlit decimal-MB browser transport cap separately from the exact MiB/byte API boundary for telemetry and evidence uploads.
- No database schema change; Alembic head remains `c31f9a7d4e20`.
- RAG remains intentionally absent until the tagged v0.9.5 archive passes final independent audit.

## v0.9.4 — Concurrency and Configuration Integrity Closure

- Serialized same-fingerprint duplicate admission through commit in the current single-process profile so concurrent identical analyses cannot both persist.
- Serialized stateful login attempts per normalized username through commit so concurrent failures cannot lose lockout-counter updates.
- Serialized refresh-token rotation per presented token through commit so simultaneous reuse cannot mint two live replacement chains.
- Serialized user-directory mutations and revalidated current administrator authority against fresh committed state, preserving the last-active-administrator invariant under concurrency.
- Serialized incident workflow mutations per incident and refreshed the transaction before applying partial PATCH semantics, preventing concurrent partial updates from overwriting one another.
- Fixed database URL configuration precedence so process environment overrides `.env`, which overrides the safe local default consistently for Alembic, bootstrap and runtime imports.
- Added exact SHA-256 pins for the official Enterprise, Mobile and ICS ATT&CK v19.1 bundles.
- Added exact build-tool/direct-dependency constraints for the verified Windows CPython 3.11 release environment.
- Corrected stale current README/release wording, report ATT&CK wording and the legacy connector-profile docstring.
- Added governed concurrency/configuration/supply-chain regressions.
- No database schema change; Alembic head remains `c31f9a7d4e20`.
- RAG remains intentionally absent.

## v0.9.3 — Correctness and Security Edge-Case Closure

- Preserved omitted incident PATCH fields and validated active investigator-eligible assignees.
- Added semantic analysis fingerprints covering telemetry content, connector/parser options, versions, rule profile and effective rule-catalogue identity.
- Added Alembic revision `c31f9a7d4e20` for semantic analysis fingerprint/context persistence.
- Reset expired timed lockouts before the next failure window and made unauthenticated account-state failures generic.
- Bounded/normalized in-memory rate-limit keys for the single-process profile.
- Made report filenames collision-safe, cleaned temporary API reports and offloaded CPU-heavy analysis work from the async event loop.
- Exactly pinned direct runtime/development dependencies and expanded correctness/security/release regressions.
- Retained 42 governed rules/126 fixtures, ATT&CK v19.1 all-domain awareness, advanced correlation, six-role RBAC and the established Linux/multi-source baselines.

## v0.9.2 — Final Pre-RAG Release-Integrity Hotfix

- Removed accidentally tracked local release ZIP packaging from the source repository.
- Added a root release-ZIP ignore rule and made repository hygiene reject tracked `ThreatLensAI_v*.zip` packages.
- Made release-manifest hashes and canonical sizes stable across Windows CRLF and Git-archive LF transformations.
- Added direct verification of generated Git-archive ZIPs against their embedded manifest.
- Added governed regressions for newline portability, ZIP hygiene, release-ZIP ignore policy and stale Upload-page labels.
- Removed stale v0.6 wording from the current Upload page and multi-source demo name.
- No Alembic schema change; database head remains `b9f7d3c2a104`.

## v0.9.1 — Quality, Security and Release-Integrity Hotfix

- Rejected known/example JWT signing secrets and changed `.env.example` to an intentionally blank secret generated by setup/bootstrap.
- Added `.streamlit/secrets.toml` to explicit Git exclusions.
- Added a framework-independent navigation policy module and governed navigation tests for all six roles.
- Added behavioral API acceptance coverage for viewer, analyst, senior analyst, incident commander, rule engineer and administrator.
- Added per-source multipart metadata so connector overrides and Linux `analysis_year` options survive the Streamlit-to-FastAPI boundary for single and multi-file analysis.
- Added strict JSON metadata validation, connector allowlisting and option allowlisting at the API boundary.
- Aligned Streamlit upload limits with authoritative API settings and aligned `.ndjson` support with connector capabilities.
- Removed Upload-page assumptions about local `AnalysisPipelineResult` properties that are absent from the remote API result contract.
- Bound FastAPI security settings to the application instance so test/deployment app factories use the exact supplied configuration.
- Added `httpx2==2.7.0` for the Starlette 1.3 TestClient backend and retained exact runtime compatibility checks.
- Expanded the governed Windows matrix from 97 to 125 tests (124 platform-independent + 1 exact runtime pin test).
- Added exact OpenAPI snapshot verification, repository security-hygiene verification and deterministic release-manifest verification.
- Added a regenerated v0.9.1 OpenAPI snapshot and release manifest; v0.9.0 artifacts remain historical and unmodified.
- No database schema change; Alembic head remains `b9f7d3c2a104`.

## v0.9.0 — FastAPI Authentication, RBAC and Security API

- Added a versioned FastAPI service boundary for analytics, cases, connectors, rules, ATT&CK, graphs, reports, users, audit and health.
- Added OAuth2 password authentication with Argon2id password hashes and signed access/refresh JWTs.
- Added short-lived access tokens, rotating refresh tokens, server-side HMAC-SHA256 token hashes, explicit logout, token-version revocation and reuse detection.
- Added persistent failed-login evidence, timed account lockout, active-account enforcement and administrator unlock/session-revocation controls.
- Added six governed roles with an explicit permission matrix: viewer, analyst, senior analyst, incident commander, rule engineer and administrator.
- Added route-level permissions and object-level incident workflow authorization.
- Added last-active-administrator protection, duplicate-email controls, password policy enforcement and session invalidation after sensitive account changes.
- Added CORS allowlisting, trusted-host enforcement, safe error envelopes, security headers, request identifiers and route-specific rate limits.
- Added strict upload filename, extension, count, empty-content and byte-size boundaries.
- Added protected OpenAPI retrieval while keeping development documentation disabled by default.
- Added authenticated PDF report generation with response SHA-256 integrity metadata.
- Added Streamlit login, token refresh, logout and a security administration page.
- Refactored Streamlit page services to use the authenticated API client instead of direct persistence access.
- Added Alembic revision b9f7d3c2a104 and persistent role, account, role-assignment, refresh-token and login-attempt tables.
- Added isolated authentication, token, lockout, RBAC, API boundary, upload and migration tests.
- Added fail-fast v0.9 security verification while retaining all v0.8 analytics, ATT&CK and correlation regressions.

## v0.8.0 — Advanced Correlation and Attack Graph Investigation

- Added deterministic cross-source entity resolution for IP, host, user, process, domain, URL, file and hash evidence.
- Added alias, source-dataset, first-seen, last-seen, alert and event provenance for canonical entities.
- Added semantic near-time alert deduplication for clustering while preserving all original alert evidence.
- Added explainable pairwise relationship scoring using shared entities, time proximity, cross-source corroboration and ATT&CK progression.
- Added configurable evidence and cluster relationship thresholds.
- Added ordered ATT&CK stage progression and multi-stage incident storylines.
- Added advanced incident names, source/entity/relationship/stage metrics and graph scores.
- Added persistent correlation runs, entities, incident-entity associations, relationships and immutable graph snapshots.
- Added SHA-256-addressed attack-graph JSON with incident, alert, entity, technique and tactic layers.
- Added the interactive Attack Graph Investigation page with graph, entity, relationship, storyline and export views.
- Added advanced correlation evidence to Current Analysis and Case Details.
- Added graph evidence and ATT&CK progression to incident PDF reports.
- Added Alembic revision a8c4e2d1f903.
- Added focused entity-resolution, correlation, persistence, graph-schema and migration-metadata tests.
- Added fail-fast v0.8 correlation verification while preserving Linux 9/4/1/0 and multi-source 22/8/2/0 results.

## v0.7.0 — Complete ATT&CK Synchronization and Coverage

- Added pinned official MITRE ATT&CK v19.1 STIX 2.1 synchronization.
- Added complete Enterprise catalog awareness: 15 tactics, 222 techniques, and 475 sub-techniques.
- Added complete Mobile catalog awareness: 12 tactics, 77 techniques, and 47 sub-techniques.
- Added complete ICS catalog awareness: 12 tactics, 79 techniques, and 18 sub-techniques.
- Added secure streamed downloads, host allowlisting, retries, atomic replacement, and SHA-256 provenance.
- Added complete STIX object and relationship persistence with raw JSON retention.
- Added versioned, evidence-backed rule mapping persistence and validation.
- Added active, revoked, deprecated, sub-technique, parent, tactic, platform, and source metadata.
- Migrated deprecated T1060 mappings to current T1547.001 with governed rule version updates.
- Added explicit ATT&CK v19 Defense Evasion taxonomy migration handling.
- Added all-domain catalog inventory, coverage gaps, and searchable technique views.
- Added ATT&CK Navigator JSON and CSV exports.
- Added the MITRE ATT&CK Coverage Streamlit page.
- Added Alembic revision f7b6c91a2d04.
- Added catalog parser, source, mapping, Navigator, persistence, and idempotency tests.
- Updated setup and fail-fast verification for all-domain official catalog acceptance.

## v0.6.0 — Governed Detection Engineering Catalogue

- Expanded the external YAML catalogue from 12 to 42 enabled rules.
- Expanded fixture evidence from 36 to 126 positive, negative and boundary cases.
- Added lifecycle ownership, reviewers, review intervals and versioned changelogs.
- Added validated allowlist and suppression configuration to the rule schema.
- Added deterministic allowlist filtering and per-analysis suppression enforcement.
- Added detailed rule-evaluation metrics for generated, allowlisted and suppressed findings.
- Added Windows account, audit, persistence, privilege and LOLBin detections.
- Added Sysmon injection, driver, image-load, registry, file, DNS, RDP and process detections.
- Added Suricata DNS tunneling, HTTP POST, TLS, SSH, file-transfer and SMB exploit rules.
- Added Zeek NXDOMAIN, long DNS, executable download, TLS SNI and failed-connection rules.
- Added cross-category Windows account-to-scheduled-task sequence correlation.
- Added default, lab and production environment-specific rule profiles.
- Added Detection Quality dashboard and CSV export.
- Added governance, fixture and dataset-distribution verification gates.
- Preserved Linux 9/4/1/0 and multi-source 22/8/2/0 regression outputs.
- Expanded the automated test suite to 46 tests.

## v0.5.0 — Multi-Source Security Telemetry

- Added Windows Security JSON/JSONL/CSV connector.
- Added Microsoft Sysmon JSON/JSONL/CSV connector.
- Added Suricata EVE JSON/JSONL connector.
- Added Zeek native TSV and JSON/JSONL connector.
- Preserved the Linux authentication connector and v0.4 regression output.
- Added confidence-based per-file source detection and diagnostic evidence.
- Added heterogeneous multi-file analysis with global event identifiers.
- Added source manifests, aggregate parser statistics and combined quarantine output.
- Added atomic multi-source persistence using deterministic source bundles.
- Expanded the rule catalogue from 4 to 12 validated YAML rules.
- Expanded fixture evidence from 12 to 36 positive, negative and boundary cases.
- Added Windows failed-logon and encoded-PowerShell detections.
- Added Sysmon LSASS-access and encoded-PowerShell detections.
- Added Suricata scanning and command-and-control alert detections.
- Added Zeek port-scan and DNS TXT-query detections.
- Added multi-source upload, source diagnostics and sample demonstration controls.
- Added the Connector Health and Coverage application page.
- Expanded the automated suite to 38 tests.
- Added exact Linux and multi-source verification gates.

## v0.4.0 — Common Schema and External Rule Engine

- Added Pydantic Common Event Schema v1.0.0.
- Added connector abstraction, registry and source auto-detection.
- Added parser statistics, data-quality findings and quarantine handling.
- Added validated Sigma-inspired YAML rule specification.
- Added generic event, threshold and sequence rule evaluation.
- Migrated all four prototype detections to YAML.
- Added 12 positive/negative/boundary fixture cases.
- Added Rule Catalog and parser-quality UI.
- Added persistence fields and Alembic revision e48a7c9d2f10.
- Expanded automated test suite to 32 tests.

## v0.3.0 — Persistent SOC Case Management

- Added explicit many-to-many alert-event evidence relationships.
- Added entity/time-based incident correlation and one attack storyline for the sample scenario.
- Corrected suspicious sudo mapping to ATT&CK T1548.003.
- Added explainable risk-factor output.
- Added full persistent analysis reload.
- Added incident-detail, note, evidence and audit read models.
- Enforced controlled incident-state transitions.
- Added modular database-backed Streamlit pages.
- Improved PDF reports with metadata, page borders, page numbers and pagination-safe tables.
- Added second Alembic migration.
- Expanded tests to 12 and raised tested-scope coverage to approximately 87%.
- Add evidence-based local model benchmarking (`scripts/benchmark_rag_models.py`) for Qwen profiles without polluting case history.
- Make exact governed-source retrieval source-oriented so multi-chunk ATT&CK documents cannot starve later explicitly requested techniques or rules.
