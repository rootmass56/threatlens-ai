# ThreatLens AI — Final Feature Guide

## Scope

This guide explains the accepted user-facing capabilities of ThreatLens AI source version **0.14.0**.

Visible navigation is permission-dependent.

## SOC Operations

### Overview

Purpose:

- summarize persisted investigations;
- surface incident posture;
- show detection-governance indicators;
- display connector/runtime/RAG status.

Use it as the operational landing page after login.

### Upload & Analyze

Purpose:

- submit supported telemetry for analysis;
- create persisted analysis sessions;
- enter the deterministic ingestion/detection pipeline.

Input handling follows connector/parser contracts and invalid data may be quarantined rather than accepted as valid evidence.

### Current Analysis

Purpose:

- inspect a selected persisted analysis;
- review normalized events;
- review deterministic alerts;
- inspect incident correlation;
- inspect quarantine and timeline information.

This is the primary evidence view for the accepted Golden Demo's `10 / 8 / 5 / 0` storyline.

### Analysis History

Purpose:

- browse persisted analyses independently of temporary browser state;
- reopen prior investigations.

### Incident Queue

Purpose:

- browse evidence-backed incidents;
- filter by workflow status;
- open an incident into Case Details.

### Case Details

Purpose:

- inspect the selected incident;
- view severity, priority, risk and confidence;
- inspect narrative/correlation;
- inspect evidence and workflow context;
- access evidence registry, notes and audit-oriented case information where populated.

### Real-Time Ingestion

Purpose:

- support live/stream-oriented ingestion workflows provided by the accepted runtime.

This capability should still be explained within the same evidence-first authority model.

### Case Operations

Purpose:

- manage investigation tasks;
- manage analyst handoffs;
- represent containment state;
- support operational case workflow.

Case Operations requires incident context. An empty page can be legitimate when no incident is selected or no workflow records exist.

## Investigation

### AI Investigation

Purpose:

- queue durable grounded investigation jobs;
- select Auto, Standard or Deep Analysis mode;
- review grounded responses and prior persisted results.

Top runtime cards expose:

- Queue;
- Workers;
- Current job;
- Result UUID.

Accepted models:

- Standard — `qwen3.5:4b`;
- Deep Analysis — `qwen3.5:9b`.

AI output is assistive and downstream of persisted deterministic evidence.

### Attack Graph

Purpose:

- visualize persisted graph/correlation artifacts;
- connect incidents, alerts, entities, tactics and techniques;
- support analyst investigation of related evidence.

Graph relationships are deterministic correlation artifacts, not LLM-created facts.

### MITRE ATT&CK

Purpose:

- browse governed ATT&CK catalog content;
- inspect techniques;
- inspect rule mappings and coverage.

ATT&CK context is governed knowledge. It must remain distinguishable from observed incident evidence.

### Rule Catalog

Purpose:

- inspect governed detection-rule information and mappings.

### Detection Quality

Purpose:

- inspect detection-quality/governance information produced by the detection engineering layer.

### Audit Trail

Purpose:

- inspect accountable operational actions;
- support traceability of authentication and governed mutations.

### Threat Intelligence

Purpose:

- manage/read governed threat-intelligence feeds and indicators;
- inspect enrichment hits;
- preserve source/provenance context.

A threat-intelligence hit is enrichment, not automatic proof of compromise.

### Threat Hunting

Purpose:

- execute bounded, read-only structured hunts over persisted events;
- use safe analyst fields such as pivot text, source IP and username;
- inspect match/returned counts and latency;
- inspect saved hunts.

Analyst-supplied SQL is not the hunt interface.

### Response Playbooks

Purpose:

- expose governed response/playbook workflows available to authorized users.

The final documentation does not claim unconstrained autonomous remediation.

### Detection Engineering

Purpose:

- support detection feedback/engineering workflows through the accepted advanced SOC surface.

### Cloud / Identity

Purpose:

- surface supported cloud/identity-oriented investigation capabilities.

### Graph Intelligence

Purpose:

- expose graph-oriented intelligence capabilities within the governed SOC workflow.

## Platform

### Connector Health

Purpose:

- inspect connector/runtime ingestion health.

### Reports

Purpose:

- generate or access supported investigation/reporting outputs.

### AI Knowledge Admin

Purpose:

- inspect/manage governed knowledge functions available to authorized administrators.

### Security Admin

Purpose:

- expose security/user administration to principals with the required permissions.

### System Health

Purpose:

- show API readiness;
- show RAG/vector readiness;
- inspect runtime administration;
- inspect observability and knowledge-index status.

## Data authority guide

Use this mental model:

| Information type | Authority |
|---|---|
| Persisted normalized telemetry | observed evidence |
| Deterministic alert | deterministic analytic artifact |
| Correlated incident | deterministic persisted case artifact |
| Case evidence/custody | analyst-preserved case evidence |
| ATT&CK catalog | governed knowledge |
| Threat-intelligence hit | enrichment |
| Attack graph edge | deterministic correlation artifact |
| LLM explanation | assistive analysis/inference |

The final row must never silently become the first row.

## Golden Demo workflow

Recommended sequence:

```text
Overview
  -> Current Analysis
  -> Incident Queue
  -> Case Details
  -> MITRE ATT&CK
  -> Attack Graph
  -> Threat Intelligence
  -> Threat Hunting
  -> Case Operations
  -> AI Investigation
  -> Audit Trail
  -> System Health
```

See [Final Demo and Interview Guide](FINAL_DEMO_AND_INTERVIEW_GUIDE.md).

## Operational references

- [Final Architecture](FINAL_ARCHITECTURE.md)
- [Deployment and Operations](FINAL_DEPLOYMENT_AND_OPERATIONS.md)
- [Security Model](FINAL_SECURITY_MODEL.md)
- [RAG / AI Architecture](FINAL_RAG_AI_ARCHITECTURE.md)
- [Troubleshooting](FINAL_TROUBLESHOOTING.md)
