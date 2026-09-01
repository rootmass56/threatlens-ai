# ThreatLens AI v0.11.1 Verification

## Governed verification target

v0.11.1 retains every deterministic, API-security, ATT&CK, correlation, grounded-RAG and adaptive-runtime gate and adds a security-closure group for dependency remediation and the built-in vector store.

Expected Windows governed matrix:

| Group | Tests |
|---|---:|
| Core + multi-source analytics | 49 |
| v0.4-v0.8 regressions | 23 |
| v0.9-v0.9.5 security/correctness/release | 101 |
| v0.10 grounded/hybrid RAG | 32 |
| v0.11 adaptive model runtime + UAT hardening | 28 |
| v0.11.1 security closure | 12 |
| Exact Windows runtime pins | 1 |
| **Total** | **246** |

Platform-independent total: **245**.

## v0.11.1 security-closure gates

`tests/test_v0111_security_closure.py` verifies:

- release version consistency;
- reviewed dependency baseline consistency;
- ChromaDB removal from runtime dependencies and active vector code;
- patched `python-multipart`, Requests and pytest pins;
- SQLite vector backend default and persistence;
- safe migration handling for the old Chroma-path environment variable;
- setup/verification dependency-attestation enforcement;
- CycloneDX source SBOM consistency;
- transitive runtime lock/SBOM generator presence and release exclusion;
- corrected verification counts;
- release-neutral third-party data notice.

## Dependency supply-chain gate

`python -m scripts.verify_dependency_security --installed` requires the exact reviewed direct pins and rejects any installed `chromadb` package.

`python -m scripts.generate_dependency_attestation` recursively walks the installed CPython 3.11 dependency graph and produces:

- `data/dependency_attestation/requirements-lock-windows-py311.txt` — exact installed transitive versions;
- `data/dependency_attestation/cyclonedx-runtime-windows-py311.json` — CycloneDX 1.6 runtime SBOM;
- `data/dependency_attestation/dependency-attestation.json` — component count and combined SHA-256.

Each component carries a SHA-256 of its installed `.dist-info/RECORD` as an environment-integrity attestation. This is deliberately labelled as an installed-distribution record hash, not a wheel-download hash.

## Live RAG gate

```powershell
$env:THREATLENS_REQUIRE_RAG_READY="1"
powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

A fully ready live gate requires:

- ThreatLens SQLite vector store ready and non-empty;
- embedding model reachable;
- Standard model installed/reachable;
- Deep model installed/reachable;
- live embedding, semantic retrieval and structured generation smoke pass.

Default models:

```text
qwen3:4b
qwen3:8b
qwen3-embedding:0.6b
```

## Upgrade index gate

v0.11.1 intentionally does not reuse Chroma runtime data. After upgrading an existing v0.11 environment:

```powershell
python -m scripts.apply_v011_adaptive_profile
python -m scripts.index_rag_knowledge --force
python -m scripts.verify_rag_runtime --require-ready
```

## Release archive gate

The source archive must exclude databases, `data/rag/`, dependency-attestation runtime artifacts, secrets, caches and nested ZIPs. It is release quality only when the embedded `RELEASE_MANIFEST_v0.11.1.json` matches every releasable archive member with zero mismatches:

```powershell
python -m scripts.verify_source_archive <archive.zip>
```
