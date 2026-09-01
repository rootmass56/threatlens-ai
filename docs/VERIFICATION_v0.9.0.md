# ThreatLens AI v0.9 Verification

## Authoritative command

```powershell
$env:THREATLENS_RULE_PROFILE = "default"
.\scripts\verify.ps1
```

## Required gates

1. Python source compilation including `api/`
2. Ruff linting
3. Ruff format verification
4. Complete Pytest suite
5. Alembic autogeneration consistency
6. Exact database head `b9f7d3c2a104`
7. 42 governed rules and 126 fixtures
8. ATT&CK v19.1 all-domain catalogue and mapping validation
9. Connector auto-detection and normalization
10. Advanced correlation and graph verification
11. FastAPI authentication/RBAC/security verification
12. Linux regression `9/4/1/0`
13. Multi-source regression `22/8/2/0`
14. Package imports and API route contract

## Security verifier

```powershell
python -m scripts.verify_security_api
```

The verifier checks the persisted six-role manifest and active administrator, then creates an isolated database and exercises:

- liveness and readiness;
- anonymous denial;
- administrator and viewer authentication;
- Argon2id password hashing;
- access/refresh token issuance;
- hashed refresh-token storage;
- refresh rotation and reuse detection;
- viewer administration denial;
- report permission;
- protected OpenAPI;
- validation error envelope;
- response security headers;
- CORS allowlist;
- required route inventory.

It must end with:

```json
"passed": true
```

## Release gate

No v0.9 commit or tag should be created unless:

- the complete verification script passes;
- login and Security Administration work in the UI;
- each role has been acceptance-tested;
- persisted sessions and roles survive restart;
- the working tree contains no runtime secrets, databases, credential files or downloaded ATT&CK bundles.
