# ThreatLens AI — Final Security Model

## Security objective

ThreatLens is designed so that security telemetry, persisted case evidence and deterministic analytics remain authoritative while high-risk actions, authentication, AI use and operational exposure stay controlled and auditable.

This document describes controls visible in the accepted source/runtime. It is not a claim of absolute security.

## Authentication

The FastAPI boundary provides password-based login and token issuance.

Important behaviors include:

- generic unauthenticated login failure messages to reduce user/account-state enumeration;
- persisted failed-login tracking;
- timed account lockout;
- access tokens;
- refresh tokens;
- refresh-token rotation;
- refresh-token reuse handling;
- explicit logout/revocation;
- authenticated `/auth/me`.

Default security settings in source include:

- access-token lifetime: 15 minutes;
- refresh-token lifetime: 8 hours;
- failed-login threshold: 5;
- lockout duration: 15 minutes.

Runtime environment variables can override supported settings.

JWT signing configuration rejects empty, short and known placeholder secrets; the configured secret must contain at least 32 characters.

## Authorization and RBAC

The frontend hides navigation the current principal is not authorized to use, but UI hiding is not the authority boundary. API-side dependencies and permissions remain required.

Examples of permission-gated capabilities include:

- analysis create/read;
- incident read;
- case operations;
- RAG query/manage;
- graph read;
- ATT&CK read;
- audit read;
- threat-intelligence read;
- hunt execution;
- response requests;
- detection feedback;
- user/security administration;
- system read.

## Browser and API boundary

The accepted API config includes:

- explicit allowed origins;
- trusted-host middleware;
- controlled HTTP methods and headers;
- security-header middleware;
- request body limiting;
- rate limiting;
- request correlation;
- observability middleware;
- sanitized validation-error responses;
- generic internal-error envelopes.

Development API documentation is disabled by default in the accepted Compose runtime.

## Secret handling

Local runtime secrets are generated into `.env.batch7.local`.

Rules:

- never commit the file;
- never print its values in documentation;
- never include secrets in screenshots;
- never store demo credentials in launchers;
- never store bearer/refresh tokens in evidence receipts;
- use `.env.example` only as a variable-name/configuration reference.

## Container posture

The accepted Compose profile applies `no-new-privileges` across core services.

API and worker containers drop all Linux capabilities.

The frontend uses the official Nginx model and restores only capabilities needed for its privilege-drop behavior (`CHOWN`, `SETGID`, `SETUID`) while listening on unprivileged port 8080.

Resource limits are configured for important application containers.

## Network exposure

Normal local operation binds the browser-facing console to loopback.

Prometheus and Grafana are also loopback-bound.

PostgreSQL and Redis are internal Compose-network services and are not directly published as standard host endpoints.

The API's internal metrics endpoint is not part of the normal public `/api/` proxy surface.

## Temporary public exposure

The Phase 9 workflow can temporarily expose the authenticated console through Cloudflare Quick Tunnel for a supervised demonstration.

Security properties of that workflow include:

- accepted source-lineage checks;
- clean-worktree checks;
- local health validation;
- HTTPS boundary validation;
- authentication remains enabled;
- internal metrics/services are not directly exposed;
- one exact `cloudflared` process is recorded;
- shutdown validates process identity before termination;
- public reachability is checked after shutdown;
- local ThreatLens health is rechecked.

This workflow is temporary and supervised. It is not a permanent deployment architecture.

## Evidence and auditability

ThreatLens persists operational audit data for authentication and governed mutations.

Case workflows can retain notes, evidence and custody events. The audit trail and evidence-custody model are part of the evidence-first design.

## AI / RAG security

Generative models are not authoritative security sensors.

Controls include:

- incident-scoped authorized context;
- governed knowledge retrieval;
- separate observed-evidence and governed-knowledge citation concepts;
- prompt-injection/secret-extraction handling;
- cross-incident isolation;
- unsupported-attribution controls;
- citation validation;
- bounded context;
- persisted assistant history/audit metadata;
- deterministic fallback behavior.

See `FINAL_RAG_AI_ARCHITECTURE.md`.

## DevSecOps

The repository contains security/release tooling for:

- CodeQL;
- Gitleaks;
- dependency review/audit;
- container scanning;
- SBOM generation;
- CI/CD release gates.

Final documentation must not imply that a scanner guarantees absence of vulnerabilities.

## Security non-goals / limitations

The project does not claim:

- zero vulnerabilities;
- autonomous incident truth from an LLM;
- permanent internet hosting;
- complete coverage of every SIEM/EDR/cloud source;
- automatic remediation without governed workflow controls;
- that a threat-intelligence hit alone proves compromise.

## Recovery principle

Never solve a security/release failure by deleting evidence or weakening controls.

Preserve:

- Git history;
- PostgreSQL state;
- Redis state;
- Ollama models;
- RAG vectors;
- release evidence.

Classify the failure first as source defect, harness defect, configuration/runtime issue or expected security control.
