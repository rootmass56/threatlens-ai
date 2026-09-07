# Batch 7 load and concurrency probes

`batch7_load.py` is intentionally bounded and uses the existing reviewed `requests` dependency. It measures actual success rate, throughput and latency rather than making unverified scale claims.

Examples:

- `python -m ops.load.batch7_load --scenario live --requests 500 --concurrency 25`
- `python -m ops.load.batch7_load --scenario ready --requests 300 --concurrency 20`
- set `THREATLENS_LOAD_PASSWORD` then run `--scenario me` for authenticated API load.

Only measured results should be quoted in the final project report or resume.
