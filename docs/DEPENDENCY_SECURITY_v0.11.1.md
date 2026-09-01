# ThreatLens AI v0.11.1 Dependency Security Closure

Review date: 2026-08-24.

The v0.11.0 independent release audit identified four dependency/supply-chain issues. v0.11.1 closes them as follows.

| Finding | v0.11.0 | v0.11.1 action |
|---|---|---|
| python-multipart request parsing advisories | 0.0.29 | upgraded to 0.0.32 |
| Requests advisory affecting `extract_zipped_paths` | 2.32.5 | upgraded to 2.34.2 |
| pytest temporary-directory advisory | 9.0.2 | upgraded to 9.0.3 |
| ChromaDB critical/high advisories with no patched 1.5.9 release | 1.5.9 | dependency removed; ThreatLens-owned SQLite vector store |

The release does not claim that unknown future vulnerabilities are impossible. Its release criterion is that the reviewed dependency contract contains no known unresolved blocker identified by the v0.11.0 independent audit and that deployment environments generate an exact transitive dependency attestation.

## Reproducibility model

Immutable source release:

- exact direct runtime/dev/build pins;
- `config/dependency_security_baseline.json`;
- CycloneDX direct-dependency source SBOM;
- no ChromaDB runtime dependency.

Installed supported Windows environment:

- exact recursively resolved transitive lock;
- CycloneDX runtime SBOM;
- installed distribution `.dist-info/RECORD` SHA-256 fingerprints;
- exact direct-pin verification;
- explicit assertion that ChromaDB is not installed.

These machine-specific runtime artifacts are deliberately excluded from source archives because binary dependency closures vary by platform and interpreter build.
## Local Streamlit UI exposure constraint

The current Streamlit dependency remains the latest published 1.61.1 release as of the review date. A confirmed upstream issue (`streamlit/streamlit#16391`) can expose stack-trace/file-path details when a malformed WebSocket protocol message reaches Streamlit's error path. No newer patched Streamlit release is available at the time of this security closure.

ThreatLens therefore treats Streamlit as a **local-development UI only** in v0.11.1:

- `.streamlit/config.toml` binds the server to `127.0.0.1`;
- `scripts/run.ps1` also forces `--server.address 127.0.0.1`;
- ordinary client error detail is disabled;
- CORS and XSRF protections remain enabled;
- public web deployment of the Streamlit UI is explicitly unsupported.

The v0.12 production-web phase replaces this local UI with the React/Next.js frontend and a separately deployed FastAPI boundary.
