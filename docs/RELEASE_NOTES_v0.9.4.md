# ThreatLens AI v0.9.4 Release Notes

v0.9.4 is a narrow deterministic pre-RAG concurrency/configuration integrity release. Deep negative testing of the immutable v0.9.3 archive found several check-then-write races and one `.env` database-selection ordering flaw that were not covered by the 144-test release design at the time v0.9.3 was tagged. v0.9.4 closes those findings without introducing RAG or changing the database schema.

## Closed findings

- Same-fingerprint duplicate analysis admission is serialized through commit in the current single-process profile.
- Stateful failed-login/lockout mutation is serialized per normalized username through commit.
- Refresh-token rotation/logout are serialized per presented token through commit, and logout follows replacement chains so a concurrent rotation cannot leave a replacement session live.
- User-directory mutations are serialized; current administrator authority is revalidated against fresh committed state before mutation, preserving at least one active administrator.
- Incident workflow, note and evidence mutations share an incident-scoped gate; workflow refreshes its transaction before applying partial PATCH semantics and object-level note/evidence authorization is rechecked after concurrent case changes.
- Database URL resolution now consistently follows process environment -> `.env` -> safe default from the database session module itself.
- Enterprise, Mobile and ICS ATT&CK v19.1 source bundles now carry exact expected SHA-256 pins in addition to collection/version/modified metadata; catalogue synchronization is serialized in the current single-process profile.
- Build tooling and direct release dependencies are exact-constrained for the verified Windows CPython 3.11 profile.
- Current README/report/connector wording was updated so historical milestone text is not presented as current behavior.

## Scope boundary

The new concurrency controls are process-local by design because v0.9.x is explicitly a single-process demonstration profile. PostgreSQL-backed distributed idempotency/locking, shared rate limiting and multi-worker operation remain v0.11 work.

Alembic head remains `c31f9a7d4e20`. The validated analytics baselines remain Linux 9/4/1/0 and five-source 22/8/2/0. The API remains 39 paths / 40 operations.
