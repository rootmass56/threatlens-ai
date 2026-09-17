# ThreatLens AI Presentation Package

This folder contains the recruiter/interviewer presentation assets for ThreatLens AI.

## Accepted Golden Demo

- Reference analysis: `93aa1e45-480d-4dbb-aae1-e4fd12db3c15`
- Reference incident: `95275eea-92f9-498a-a975-74f53906e803` (`Multi-Stage Credential Access Activity`)
- 10 normalized events
- 8 alerts
- 5 correlated incidents
- 0 quarantined records
- RAG: pgvector / 1007 indexed chunks

The accepted Golden Demo remains the primary deterministic investigation story.

## Case Operations presentation scenario

Case Operations uses a separate namespaced, non-reference Batch-6 incident:

- Marker: `PHASE7D-CASEOPS-DEMO-V1`
- Incident identity: resolve from the namespaced persisted presentation context; do not hard-code a numeric database ID
- Tasks: 3
- Handoffs: 1
- Containment: in_progress

The accepted Golden Demo incident was not altered to manufacture Case Operations activity.

## AI Investigation UI repair

The Phase7 presentation branch contains a one-file frontend repair to the AI Investigation summary metrics.

- Repair commit: 8c3aa08c36a46f982ce8f5f765c68a47d03647d5
- Changed path: frontend/src/pages/AiPage.tsx
- Backend/RAG/DB semantics: unchanged
- Frontend build: PASS
- Runtime/RAG validation: PASS

## Screenshot sequence

S01 Public Showcase
S02 Secure Login
S03 Overview
S04 Current Analysis
S05 Incident Queue
S06 Case Details
S07 MITRE ATT&CK
S08 Attack Graph
S09 Threat Intelligence
S10 Threat Hunting
S11 Case Operations
S12 AI Investigation
S13 Audit Trail
S14 System Health

Screenshots must not expose passwords, tokens, .env content, private keys, or other secrets.