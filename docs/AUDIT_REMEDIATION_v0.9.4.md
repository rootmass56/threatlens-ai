# ThreatLens AI v0.9.4 Deep-Audit Remediation

The exact tagged `ThreatLensAI_v0.9.3_FINAL.zip` passed its declared release gates but deeper concurrent and configuration-order testing reproduced additional defects. v0.9.4 is the corrective release.

| Finding | Severity | v0.9.4 control |
|---|---|---|
| Concurrent identical semantic analyses can both persist | High | bounded fingerprint-keyed lock held through transaction commit |
| Concurrent refresh of one token can mint two replacement chains | High | token-keyed rotation lock held through commit |
| Concurrent failed logins lose increments and bypass lockout | High | normalized-username login lock held through commit |
| Two administrators can concurrently disable each other | High | serialized user-directory mutations + fresh actor authority revalidation |
| `.env` database URL can be ignored by Alembic/bootstrap import order | High | database session resolves process env, then `.env`, then default itself |
| Concurrent partial incident workflow updates can overwrite state | Medium | incident-keyed mutation serialization + fresh workflow transaction |
| Concurrent reassignment can race analyst note/evidence authorization | Medium | note/evidence share the incident mutation gate and recheck object authorization |
| Refresh and logout can race across a token replacement | Medium-High | shared token gate + descendant replacement-chain revocation |
| ATT&CK source identity lacks exact content pin | Medium hardening | exact official v19.1 SHA-256 pins |
| Concurrent ATT&CK synchronization can race unique/active catalogue state | Medium | process-local re-entrant synchronization gate |
| Current release docs/report wording stale | Low | current v0.9.4 documentation/runtime copy corrected |

These controls are covered by new v0.9.4 tests and must also pass the complete Windows release gate and tagged-archive verification before v0.10 begins.
