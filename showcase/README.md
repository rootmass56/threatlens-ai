# ThreatLens AI — Public Showcase

This directory is the Phase-6 recruiter-facing public showcase for ThreatLens AI.

## Security model

The showcase is intentionally static and sanitized:

- no operational FastAPI endpoint is exposed;
- no authentication or admin surface is exposed;
- no PostgreSQL, Redis, worker, Ollama, Prometheus, or Grafana endpoint is exposed;
- no telemetry upload, analyst action, form, or AI prompt is accepted;
- no JavaScript is required;
- no analytics, cookies, trackers, external fonts, external images, or third-party runtime resources are used;
- no environment variable or runtime secret is required.

The page uses a restrictive meta Content Security Policy with `script-src 'none'` and `connect-src 'none'`.

## Files

- `index.html` — semantic single-page portfolio content.
- `styles.css` — responsive dependency-free visual design.
- `showcase-manifest.json` — machine-readable sanitized claim/behavior manifest.
- `README.md` — this deployment and security contract.

## Deployment contract

Deploy the contents of this directory as a static site root. There is no build command and no runtime environment variable.

The hosting provider must provide HTTPS. Provider-specific security headers, caching, and canonical-domain configuration are added and verified in Phase 6C.

Do not add the operational `.env` file, credentials, private repository URLs, live API endpoints, database endpoints, model endpoints, or observability/admin URLs to this directory.

## Claims

The metrics shown on the public page are accepted local project validation results. They are intentionally labeled as local acceptance/benchmark evidence rather than universal production guarantees.

The public Golden Demo story remains:

- 10 normalized events
- 8 alerts
- 5 correlated incidents
- 0 quarantined records

AI remains downstream of deterministic persisted evidence in every public description.