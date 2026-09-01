# ThreatLens YAML Rule Authoring Guide

## Required governance fields

Every rule requires a UUID, detection name, version, status, author, dates, description, log source, detection definition, severity, confidence, message, ATT&CK mapping, false positives, response, risk metadata and fixture manifest.

## Rule kinds

### Event

Creates one alert for each event matching the condition.

### Threshold

Creates an alert when a selection reaches a configured count within a group and time window. Optional distinct-count logic is supported.

### Sequence

Creates an alert when ordered stages occur within a time window and entity group.

## Operators

- `equals` (default)
- `not_equals`
- `contains`
- `not_contains`
- `starts_with`
- `ends_with`
- `regex`
- `in`
- `exists`
- `greater_than`
- `less_than`

Expression examples:

```yaml
process_name: powershell.exe
command_line|contains: -EncodedCommand
source_port|greater_than: 1024
username|exists: true
```

## Conditions

Supported forms:

- `selection`
- `selection_a and selection_b`
- `selection_a or selection_b`
- `selection_a and not filter_known`
- `all of them`
- `any of them`
- `1 of prefix*`

Conditions are interpreted through a restricted boolean AST. Arbitrary Python execution is not permitted.

## Fixture gate

A stable rule must have positive, negative and boundary cases in its manifest. Run:

```powershell
python scripts\validate_rules.py
```

The process returns non-zero when validation or a fixture fails.

## ATT&CK integrity

Every rule requires exactly one primary mapping. Secondary mappings are optional. A mapping must contain a valid technique ID, technique name, tactic, confidence and evidence-based justification.

## v0.6 lifecycle requirements

Every rule must now include `lifecycle` and `tuning` sections. Use an owner group rather than an individual where possible, include at least one reviewer, set a review interval and add a changelog record for the active version.

### Example lifecycle

```yaml
lifecycle:
  owner: ThreatLens AI Detection Engineering
  reviewers:
    - SOC Engineering
    - Security Architecture
  last_reviewed: '2026-08-05'
  review_interval_days: 90
  changelog:
    - version: 1
      date: '2026-08-05'
      summary: Initial governed release.
```

### Example tuning

```yaml
tuning:
  allowlists:
    - name: approved_scanners
      reason: Exclude approved vulnerability scanners.
      enabled: true
      expressions:
        source_ip|in:
          - 192.0.2.10
  suppression:
    enabled: true
    group_by:
      - source_ip
    timeframe_minutes: 30
    max_alerts: 1
  parameters:
    profile: default
```

Allowlists must document a reason. Suppression must group on at least one event field when enabled.
