# ThreatLens AI v0.9.0 Release Notes

## Headline

ThreatLens AI now operates behind an authenticated FastAPI service boundary with persistent users, governed RBAC, account lockout, rotating refresh tokens, protected API documentation and an API-backed Streamlit interface.

## Major additions

- OAuth2 password authentication
- Argon2id password hashes
- Access/refresh JWT lifecycle
- Refresh-token rotation, hashing, revocation and reuse detection
- Six governed roles and explicit permissions
- Object-level case authorization
- User, role, unlock and session administration
- Rate limits, security headers, CORS and trusted hosts
- Safe validation and error envelopes
- Strict upload controls
- Protected OpenAPI contract
- Authenticated report generation and integrity hash
- Security administration UI
- Security database migration and bootstrap
- Focused API/RBAC security verification

## Compatibility

All v0.8 analyses, ATT&CK catalogues, cases and attack graphs remain compatible. Existing v0.8 databases require the v0.9 Alembic migration and security bootstrap before the UI can be used.

## Known limitations

- Local HTTP only; HTTPS is a v0.11 deployment control.
- Rate limits are process-local.
- SQLite remains the development profile.
- No external identity provider or MFA.
- Rule mutation endpoints are reserved for future controlled implementation; v0.9 provides read and ATT&CK synchronization authority.
