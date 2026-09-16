# ThreatLens AI Speaker Notes

## S01 Public Showcase
"This is the recruiter-safe static surface. The operational console is not publicly exposed here."

## S02 Secure Login
"The operational SOC console is authenticated and RBAC-protected."

## S03-S10 Investigation flow
"The accepted Golden Demo is 10 normalized events, 8 alerts, 5 correlated incidents, and 0 quarantined records. The key point is traceability from telemetry to evidence, detections, incidents, ATT&CK context, graph context, intelligence, and hunting."

## S11 Case Operations
"This screen uses a separate namespaced presentation incident because the accepted Golden Demo had no task/handoff records. I did not alter the accepted incident just to improve a screenshot. The scenario demonstrates real persisted tasks, handoffs, and containment state."

## S12 AI Investigation
"AI is downstream of evidence. Queue state, durable workers, model profiles, retrieved evidence, citations, grounding, and persisted RAG results are all visible. AI does not establish authoritative incident facts."

## S13 Audit Trail
"Security-sensitive actions and investigation activity remain auditable."

## S14 System Health
"The system closes with runtime, observability, RAG, vector, and model readiness."
## RAG readiness marker

ThreatLens AI uses pgvector with 1007 indexed chunks for the accepted presentation baseline.