# ThreatLens AI presentation assets

This directory contains the static recruiter/interviewer deck, diagrams, speaker notes, and archived UI captures. The screenshots illustrate interface capabilities; their on-screen counts are **not** a live runtime health result or a current global total.

## Which investigation should I present?

For the current post-release portfolio scenario, use the [Enhanced Golden Demo v2](../demo/README_ENHANCED_DEMO_V2.md): five telemetry sources, 29 normalized events, 26 deterministic alerts, 2 critical correlated incidents, and 0 quarantined records. Its acceptance contract also records 19 ATT&CK techniques, 21 resolved entities, 139 scored relationships, and a 76-node / 300-edge persisted attack graph. These are fixture-specific results, not universal detection or performance claims.

The immutable v1.0.0 acceptance reference is a **different** dataset: 10 events, 8 alerts, 5 incidents, 0 quarantined. Keep its evidence separate from the enhanced v2 scenario. See the [demo guide](../docs/FINAL_DEMO_AND_INTERVIEW_GUIDE.md) for the correct walkthrough and the [operations guide](../docs/FINAL_DEPLOYMENT_AND_OPERATIONS.md) for startup commands.

## Contents

- `ThreatLensAI_Recruiter_Interviewer_Deck.html`: static presenter deck; it does not expose the authenticated backend.
- `DEMO_NARRATIVE.md` and `SPEAKER_NOTES.md`: presentation narrative and supporting notes. Validate any historical counts against the selected demo contract.
- `assets/`: architecture and trust-boundary diagrams.
- `assets/screenshots/S01`–`S14`: archived captures covering the public showcase, login, overview, analysis, incidents, ATT&CK, graph, threat intelligence, hunting, case operations, AI, audit trail, and system health.

The operational SOC console is local and authenticated. The public showcase is a separate static surface; neither an archived screenshot nor the static deck is proof that a live service is running.

## Before sharing or recording

Use only synthetic/authorized telemetry. Review every capture for personal data and do not expose passwords, tokens, `.env` content, private keys, or live infrastructure identifiers. Cite project-owned screenshots as repository captures and distinguish generated report figures from archived UI images.
