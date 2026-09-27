# ThreatLens dependency SBOMs

`source-dependencies-v0.14.0.cdx.json` is the current source-line CycloneDX 1.6 inventory of every reviewed direct build, runtime and development pin. Historical SBOMs remain available from their immutable Git tags and release history.

The supported Windows setup also runs `python -m scripts.generate_dependency_attestation`. That command walks the *installed* Python 3.11 dependency graph recursively, writes an exact transitive `requirements-lock-windows-py311.txt`, emits `cyclonedx-runtime-windows-py311.json`, and records SHA-256 fingerprints of each installed distribution's `.dist-info/RECORD`. Those machine/runtime artifacts are written under `data/dependency_attestation/` and intentionally excluded from the immutable source ZIP because they are platform-specific.

The source release therefore preserves the reviewed direct contract while each deployment receives an exact transitive environment attestation generated from what is actually installed.
