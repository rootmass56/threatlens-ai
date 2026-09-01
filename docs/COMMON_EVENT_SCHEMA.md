# Common Event Schema v1.0.0

## Purpose

The common schema prevents detection rules and correlation logic from depending on one vendor-specific format. Linux, Windows, endpoint, network and cloud connectors must normalize into the same contract.

## Field groups

### Identity and version

- `schema_version`
- `event_uuid`
- `external_event_id`

### Time

- `timestamp` — timezone-aware UTC
- `original_timestamp`
- `timezone`

### Source classification

- `source_category`
- `source_product`
- `source_service`
- `source_dataset`

### Event semantics

- `event_type`
- `event_action`
- `event_outcome`

### Network

- `source_ip`
- `source_port`
- `destination_ip`
- `destination_port`

### Identity and host

- `username`
- `hostname`

### Process

- `process_name`
- `process_id`
- `parent_process_name`
- `command_line`

### Resource and application

- `file_path`
- `domain`
- `url`

### Evidence and parser context

- `raw_message`
- `normalized_message`
- `parser_name`
- `parser_version`
- `parse_status`
- `data_quality`
- `attributes`

## Parse status

- `parsed` — fully recognized record
- `partial` — envelope parsed but one or more semantics are unknown
- `quarantined` — represented through `QuarantinedRecord` because safe normalization failed

Records are never silently discarded. Empty lines are counted separately in parser statistics.
