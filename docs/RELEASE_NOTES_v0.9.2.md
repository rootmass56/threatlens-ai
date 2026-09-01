# ThreatLens AI v0.9.2 Release Notes

v0.9.2 is the final pre-RAG release-integrity hotfix. It does not change the deterministic detection/correlation architecture or database schema. Alembic remains at `b9f7d3c2a104`.

## Closed findings

- local release ZIPs are kept outside the Git source repository;
- repository hygiene rejects tracked `ThreatLensAI_v*.zip` packaging archives;
- release-manifest hashes canonicalize UTF-8 text line endings to LF;
- `scripts.verify_source_archive` validates the actual distributable ZIP against its embedded manifest;
- current Upload-page text no longer carries stale v0.6 milestone labels;
- governed regression coverage includes the v0.9.2 release-integrity controls.
