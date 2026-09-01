# ThreatLens AI v0.11.1 Release Notes

## Security closure

v0.11.1 closes the independent post-freeze audit findings from v0.11.0.

### Dependency remediation

- `python-multipart` 0.0.29 -> 0.0.32;
- Requests 2.32.5 -> 2.34.2;
- pytest 9.0.2 -> 9.0.3;
- ChromaDB 1.5.9 removed completely from runtime dependencies.

The reviewed dependency baseline is stored in `config/dependency_security_baseline.json` and enforced by `scripts.verify_dependency_security`.

### ThreatLens-owned vector persistence

The production vector backend is now `SQLiteVectorStore`, implemented with Python's built-in `sqlite3` module. The store persists governed chunk text, provenance metadata and embedding vectors in a local SQLite database and performs deterministic exact cosine ranking. Exact ATT&CK/rule source lookup and the existing hybrid retrieval interface are unchanged.

This removes the Chroma server/client attack surface and keeps vector persistence within the same audited local-storage boundary as the rest of the demonstration platform.

Existing Chroma runtime index files are not reused. The governed corpus must be re-indexed once after upgrade.

### Dependency reproducibility and SBOMs

The source release includes a CycloneDX 1.6 direct-dependency inventory. Supported Windows setup additionally captures the exact recursive installed dependency closure, CycloneDX runtime SBOM and installed-distribution record hashes under `data/dependency_attestation/`.

### Documentation closure

Verification counts, runtime configuration names, third-party data language, release version references and dependency documentation have been corrected for v0.11.1.

### Compatibility

- FastAPI contract remains 44 paths / 45 operations.
- Alembic head remains `d4a7c0e51010`.
- Database schema remains compatible.
- Standard/Deep model profiles remain `qwen3:4b` / `qwen3:8b`.
- Embeddings remain `qwen3-embedding:0.6b` at 1024 dimensions in the validated local setup.
- All deterministic analytics and RAG trust-boundary controls remain authoritative.
