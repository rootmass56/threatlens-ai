# ThreatLens AI v0.9.2 Tagged-Archive Audit Remediation

| Finding | v0.9.2 control |
|---|---|
| v0.9.1 manifest failed after Git-archive LF normalization | Canonical UTF-8 LF hashing and canonical size |
| v0.9.0 source ZIP tracked inside v0.9.1 | Removed from Git; root release ZIPs ignored |
| Hygiene did not reject tracked release packages | `ThreatLensAI_v*.zip` is forbidden when tracked |
| No direct distributable ZIP verification | `scripts.verify_source_archive` |
| Current Upload UI still said v0.6 | Version-neutral Upload text |
