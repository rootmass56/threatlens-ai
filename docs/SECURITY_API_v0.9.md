# ThreatLens AI v0.9 Security API

## Purpose

The v0.9 FastAPI layer is the mandatory trust boundary between the Streamlit analyst interface and ThreatLens application services. It centralizes authentication, authorization, request validation, safe errors, rate limits, audit attribution and protected service contracts.

The architecture is a modular monolith with explicit boundaries:

```text
Browser
  -> Streamlit UI
      -> authenticated HTTP requests
          -> FastAPI security boundary
              -> application services
                  -> domain engines and repositories
                      -> SQLite development database
```

Streamlit holds access and refresh tokens only in its server-side session state. It no longer creates database sessions or repositories for page workflows.

## Authentication design

- OAuth2 password form at `/api/v1/auth/login`.
- Argon2id password hashing with unique salts.
- HMAC-signed JWT access and refresh tokens.
- Issuer, audience, token type, JTI, subject, token version, issued-at, not-before and expiration claims.
- Short-lived access tokens; default 15 minutes.
- Rotating refresh tokens; default eight hours.
- Refresh-token hashes persisted with HMAC-SHA256; plaintext refresh tokens are never stored.
- Reuse of a revoked refresh token increments the account token version, invalidating all older access and refresh tokens.
- Explicit logout revokes the supplied refresh token.
- Password, role, active-state and administrative session changes invalidate existing sessions.

## Account protections

- Normalized unique usernames.
- Unique optional email addresses.
- Password length and composition policy.
- Persistent failed-login count.
- Persistent login-attempt evidence containing username, source IP, result, reason and request ID.
- Timed lockout after the configured threshold.
- Disabled account enforcement on login, access-token use and refresh-token use.
- Administrator unlock and session revocation.
- Last-active-administrator protection.
- Current administrator self-disable and self-role-removal protection.

## API security controls

### Input boundary

- Pydantic models reject unknown fields.
- String lengths, patterns and enums are constrained.
- Upload count and byte limits are environment-configurable.
- Allowed upload extensions are `.log`, `.txt`, `.json`, `.jsonl` and `.csv`.
- Windows and POSIX path components are stripped from uploaded filenames.
- Empty files and control characters are rejected.
- Connector override is restricted to single-file analysis.

### Network and browser boundary

- CORS uses an explicit origin allowlist.
- Trusted-host middleware rejects unapproved host headers.
- Security headers include `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control` and a restrictive API Content Security Policy.
- Every response receives an `X-Request-ID`.
- Rate-limit metadata is returned to clients.

### Error boundary

All API errors use a stable envelope:

```json
{
  "error": {
    "code": "permission_denied",
    "message": "The authenticated role does not permit this operation.",
    "request_id": "...",
    "details": {}
  }
}
```

Validation errors expose field locations and safe messages without stack traces, database statements, secrets or filesystem paths. Unexpected exceptions are logged server-side with the request ID and return a generic response.

## Documentation boundary

Default FastAPI Swagger, ReDoc and public OpenAPI endpoints are disabled. Users with `docs:view` can retrieve the contract from `/api/v1/system/openapi` or the Security Administration page. Development Swagger can be enabled explicitly for local use only.

## Rate-limiting scope

v0.9 uses an in-memory per-process fixed-window limiter appropriate for the single-process semester demonstration profile. It protects login, token refresh, upload and general API routes. A distributed deployment in v0.11 must replace it with a shared backend such as Redis or a gateway-managed limit.

## Audit attribution

Authentication and user-administration changes create audit records. Existing case-management service operations continue to record workflow, note and evidence actions. The API always derives the actor from the authenticated principal; client-supplied actor fields are ignored.

## Security limitations

- TLS termination is not implemented in v0.9 local execution; v0.11 deployment must place services behind an HTTPS-capable reverse proxy.
- Access tokens remain usable until expiration unless account token version, active state or role/password changes invalidate them.
- The rate limiter is process-local.
- SQLite remains the local profile and does not represent production concurrency.
- v0.9 does not implement external identity providers, MFA or autonomous response actions.
