# Detection Engineering Architecture — v0.6

## Design goals

The v0.6 rule system is designed around five requirements:

1. Deterministic and explainable behavior.
2. Complete fixture evidence for every rule.
3. Explicit ownership and review responsibility.
4. Tunable false-positive controls without unsafe code execution.
5. Reproducible catalogue quality metrics.

## Rule lifecycle

Every rule must include:

- `lifecycle.owner`
- `lifecycle.reviewers`
- `lifecycle.last_reviewed`
- `lifecycle.review_interval_days`
- `lifecycle.changelog`

Stable rules require a changelog entry for the active version. Deprecated rules require a reason and may reference a replacement rule UUID.

## Tuning controls

### Allowlists

Allowlists use the same validated field-expression grammar as detections. Matching events are removed before detection evaluation. This prevents approved assets, identities or processes from creating findings while retaining explicit documentation of why the exclusion exists.

### Suppression

Suppression executes after a rule match. The engine builds a deterministic key from configured fields and limits the number of alerts within the configured time window. Suppression does not delete evidence; it reduces repeated findings during one analysis.

### Profiles

`config/rule_profiles.yml` allows approved overrides for:

- rule enablement
- severity
- confidence
- threshold count/timeframe
- suppression configuration

Unsupported override fields are rejected.

## Fixture standard

Each manifest must provide at least:

- one `positive` case that must alert
- one `negative` case that must remain quiet
- one `boundary` case testing threshold, time, allowlist or near-match behavior

The validator checks manifest-to-rule identity, case types, duplicate names, expected alert counts, path safety and fixture-file existence.

## Quality model

The Detection Quality page calculates:

- lifecycle completeness
- fixture completeness
- governance score
- review state
- rule distribution by dataset
- rule distribution by severity
- rule distribution by ATT&CK tactic
- allowlist and suppression coverage

## Safety properties

- No direct `eval` execution.
- Regex length and syntax validation.
- Restricted boolean condition AST.
- Maximum expression-value counts.
- Path traversal prevention for fixtures.
- Typed Pydantic rule schema.
- Profile override allowlist.
