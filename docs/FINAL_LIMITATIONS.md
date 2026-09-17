# ThreatLens AI — Final Limitations and Non-Goals

## Why this document exists

ThreatLens AI is intentionally documented with explicit boundaries. A technically strong project should state what has been accepted and what has **not** been demonstrated or guaranteed.

Current source version: **0.14.0**.

Final v1.0.0 release remains pending final Phase 10 acceptance.

## 1. AI is not authoritative incident evidence

The LLM can summarize and reason over authorized evidence, but it does not establish that an attack occurred.

Deterministic persisted evidence remains authoritative.

This is a design boundary, not a temporary limitation to remove.

## 2. No zero-hallucination guarantee

Grounding, citation validation, scoped retrieval and adversarial testing reduce risk, but no generative model is documented as incapable of error.

Unsupported answers should be constrained, rejected, marked out-of-scope/partially supported, or degraded rather than silently promoted to fact.

## 3. No zero-vulnerability guarantee

The repository includes security controls and DevSecOps scanning, but no scanner or release gate proves that the system contains no vulnerabilities.

## 4. The accepted final-project runtime is local-first

The accepted production-style runtime is Docker Compose on a local workstation.

The project includes:

- a static public showcase;
- a supervised temporary internet-demo workflow.

It does **not** claim that the authenticated operational console is permanently hosted as a public production SaaS service.

## 5. Temporary internet exposure is intentionally temporary

The Phase 9 Quick Tunnel workflow is for supervised demonstrations.

It uses a random temporary public URL and must be revoked after the demo.

It is not a substitute for a permanent production ingress architecture with a stable domain, managed TLS, enterprise identity, dedicated WAF/CDN policy and production hosting operations.

## 6. Corpus size is not a permanent invariant

The accepted RAG runtime currently reports **1007 indexed chunks**.

That number reflects the accepted governed corpus state. An intentional future corpus/index change may legitimately alter it and would require fresh acceptance evidence.

## 7. Model latency depends on local hardware

Standard and Deep Analysis use local models.

Performance depends on:

- CPU/GPU/NPU availability;
- memory;
- model residency;
- context size;
- concurrent requests;
- host load.

Deep Analysis can be materially slower than Standard on constrained hardware.

## 8. Connector coverage is finite

ThreatLens supports a defined set of telemetry/connectors exercised by the project.

The final documentation does not claim compatibility with every SIEM, EDR, cloud, network or identity product.

Adding a new source requires a governed parser/normalization/detection integration rather than assuming arbitrary JSON is automatically understood.

## 9. Detection coverage is not universal

A governed rule catalog does not guarantee detection of every adversary technique or every variant of a technique.

ATT&CK coverage and rule mappings describe implemented knowledge/detection relationships; they are not a proof of complete defensive coverage.

## 10. Threat intelligence is enrichment

An IOC/feed match alone does not prove malicious activity in the local environment.

Threat intelligence must remain distinct from observed telemetry and incident evidence.

## 11. Threat Hunting is deliberately bounded

The hunt interface is designed around read-only structured fields.

This reduces the risk of unrestricted analyst-provided SQL reaching the database, but it also means the hunt language is intentionally narrower than direct SQL.

## 12. Case workflow completeness depends on selected context

Case Operations requires an incident context and may legitimately show no tasks/handoffs when none have been created for that incident.

A populated presentation case should not be confused with universal workflow state across every incident.

## 13. Presentation data and product truth must remain separated

Presentation-only workflow records may be created for a demo when explicitly permitted by the release contract.

Such records must not overwrite or falsify the frozen accepted Golden Demo reference evidence.

## 14. Historical documentation can contain stale architecture

The repository preserves older versioned documents for traceability.

Those files may describe earlier:

- deployment targets;
- vector-store choices;
- test counts;
- API counts;
- rule counts;
- UAT entrypoints.

Use the `FINAL_*` documentation and accepted source/release evidence for current claims.

## 15. Exact historical test counts are not current guarantees

Older documents can contain exact counts that were true for a prior source state.

The final documentation intentionally avoids reusing them as current numbers unless they are re-derived from the accepted current source.

## 16. Observability is project-grade, not a managed enterprise operations service

Prometheus/Grafana/exporters provide real runtime observability for the accepted stack.

The project does not claim that this alone provides a complete enterprise NOC/SOC monitoring program, 24x7 on-call operations or managed alert routing.

## 17. Availability is not documented as multi-region/high-availability

The accepted runtime proves controlled recovery and restart behavior.

It is not documented as a multi-region, active-active, automatically failover-managed production service.

## 18. Identity integration is application-local for the accepted project

The final project documents its own authenticated user/RBAC flow.

It does not claim accepted enterprise SSO federation, SCIM provisioning, hardware-backed MFA or organization-wide IAM integration unless a future release explicitly adds and validates those controls.

## 19. Automated remediation is intentionally governed

The project includes response/playbook-oriented capabilities, but final documentation does not claim unconstrained autonomous containment or remediation.

Security response actions should remain permissioned and auditable.

## 20. Final v1.0.0 is still a release gate decision

Phase 8 documentation completion is not the same thing as final release.

The final tag/release decision belongs to Phase 10.

Until then, the precise statement is:

> ThreatLens AI source version 0.14.0 has completed accepted engineering, demo and documentation phases toward the final v1.0.0 release candidate, with final release acceptance still pending.

## Related documents

- [Final Architecture](FINAL_ARCHITECTURE.md)
- [Security Model](FINAL_SECURITY_MODEL.md)
- [RAG / AI Architecture](FINAL_RAG_AI_ARCHITECTURE.md)
- [Testing and Validation](FINAL_TESTING_AND_VALIDATION.md)
- [Demo and Interview Guide](FINAL_DEMO_AND_INTERVIEW_GUIDE.md)
