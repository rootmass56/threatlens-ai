# ThreatLens AI v0.9 API Security Threat Model

## Assets

- Security telemetry and normalized events
- Detection alerts and ATT&CK mappings
- Incident cases, assignments, notes and evidence
- Attack graphs and reports
- User accounts, role assignments and password hashes
- Access and refresh tokens
- Audit history
- JWT signing secret and environment configuration

## Trust boundaries

1. Browser to Streamlit
2. Streamlit to FastAPI
3. FastAPI to application services
4. Application services to persistence
5. File upload to parser boundary
6. Administrator to user/security administration
7. ATT&CK synchronization to external official data source

## Primary threats and controls

| Threat | v0.9 control | Residual limitation |
|---|---|---|
| Credential guessing | Login rate limit, persistent failure count, timed lockout | Distributed attacks require shared/gateway limiting |
| Password disclosure | Argon2id hashes, no plaintext persistence | Endpoint security remains external |
| Token database theft | Refresh tokens stored as keyed hashes | Active access tokens remain bearer credentials |
| Refresh-token replay | Rotation, revocation and reuse detection | Token theft before first use is still possible |
| Privilege escalation | Explicit permission dependencies and object checks | Policy defects require continued negative testing |
| IDOR | Incident object authorization | Future resources require equivalent checks |
| Last-admin lockout | Active-administrator preservation | Manual database changes are outside API controls |
| Injection | Typed validation, SQLAlchemy, controlled service calls | Parser-specific content still requires fuzz testing |
| Path traversal | Basename normalization and extension allowlist | Uploaded content itself remains untrusted |
| Oversized upload | File count and byte limits | Reverse proxy limits are deferred to v0.11 |
| Host-header abuse | Trusted-host allowlist | LAN use needs explicit configuration |
| Cross-origin abuse | CORS allowlist | CORS is not a substitute for authentication |
| Clickjacking | `X-Frame-Options: DENY`, CSP frame ancestors | Streamlit headers are deployment-layer work |
| Sensitive error leakage | Safe envelopes and generic 500 responses | Server logs must be protected |
| Public API enumeration | Swagger/OpenAPI disabled publicly | Protected schema remains visible to administrators |
| Audit spoofing | Actor derived from access-token principal | Immutable external audit storage is future work |
| Session persistence after role change | Token version and refresh revocation | Already-issued requests cannot be recalled |
| Denial of service | Local rate limits and upload limits | Multi-instance/global controls deferred |

## Abuse cases covered by automated verification

- Anonymous access to protected routes
- Viewer access to administrator routes
- Weak passwords
- Duplicate email and role input
- Failed-login lockout
- Disabled-account login
- Refresh-token rotation and reuse
- Logout and refresh-token revocation
- Missing/invalid request data
- Unsupported and empty uploads
- Protected OpenAPI authorization
- CORS allowlist behavior
- Security-header presence
- Last-administrator protection

## Deferred controls

v0.11 must add HTTPS termination, shared rate limiting, secret injection, container isolation, PostgreSQL least-privilege users, backup encryption, health/readiness orchestration, structured centralized logs and deployment hardening. v1.0 must add dedicated authorization-bypass, SQL-injection, file-abuse and fuzzing programmes.
