# ThreatLens AI v0.12 — Full React Local UAT

Use `RUN_THREATLENS_V012_UAT.ps1` after the full release gate passes. The runner avoids Windows-reserved port 8000 by probing a safe backend port and binds Vite explicitly to `127.0.0.1`.

## UAT sequence

1. **Authentication** — sign in with the v0.12 administrator; confirm bad credentials fail safely.
2. **Overview** — confirm analysis/incident metrics and RAG status match persisted data.
3. **Upload & Analyze** — upload Linux, Windows Security, Sysmon, Suricata and Zeek samples; confirm multi-source auto-detection.
4. **Current Analysis** — verify sources, events, alerts, incidents, timeline, quarantine and correlation tables.
5. **Analysis History** — reload an existing persisted session and export CSV.
6. **Incident Queue** — filter lifecycle states and open a case.
7. **Case Details** — validate incident narrative, alerts, events, entities, relationships and persisted attack graph.
8. **Workflow** — assign/update status and priority under RBAC; verify unauthorized roles are denied.
9. **Evidence Registry / Notes** — add evidence metadata and investigation notes; verify audit entries.
10. **AI Standard** — query a case using Qwen3.5:4b and verify citations/grounding.
11. **AI Deep** — query a complex case using Qwen3.5:9b and verify routing metadata.
12. **AI Auto** — verify routine questions route Standard and complex questions route Deep.
13. **Prompt-injection protection** — submit an instruction to reveal/ignore system controls and verify safe refusal/out-of-scope handling.
14. **ATT&CK** — inspect all-domain catalogue data, mappings/gaps, Navigator export and privileged sync behavior.
15. **Detection Engineering** — rule catalogue, details, validation, fixtures, quality and profiles.
16. **Connector Health** — registry and file diagnostics.
17. **Reports** — generate a PDF and record the server-provided SHA-256.
18. **Audit Trail** — confirm recent workflow/note/RAG/admin actions are visible.
19. **Administration** — validate users/roles and protected OpenAPI according to role permissions.
20. **System & RAG** — validate runtime profiles and knowledge status; do not force re-index unless required.
21. **Session lifecycle** — let an access token age, confirm refresh rotation keeps the session usable, then sign out.
22. **Responsive layout** — verify desktop, narrow desktop/tablet and mobile breakpoints.

A production deployment cannot be frozen solely on automated tests; this UAT must also pass against the React console and migrated/representative data.
