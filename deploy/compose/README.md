# Compose configurations

The supported local runtime is defined by [`../../compose.yaml`](../../compose.yaml) and is started through the root [`START_THREATLENS.ps1`](../../START_THREATLENS.ps1) command.

| Path | Purpose | Support level |
| --- | --- | --- |
| `../../compose.yaml` | Current Batch 7 production-style runtime | Supported |
| `internet-demo.override.yml` | Temporary Cloudflare demo overlay used with the current runtime | Demo only |
| `legacy/batch5.yml` | Batch 5 migration and regression contract | Historical compatibility |
| `legacy/batch6.yml` | Batch 6 migration and regression contract | Historical compatibility |

The legacy definitions are retained for governed migration and regression checks. They are not recommended for new deployments.
