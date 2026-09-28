# Demo launchers

Run these commands from the repository root after bootstrapping the Batch 7 environment.

| Command | Purpose |
| --- | --- |
| `.\scripts\demo\start-enhanced-demo-v2.ps1` | Final portfolio investigation |
| `.\scripts\demo\start-golden-demo.ps1` | Frozen v1 acceptance scenario |
| `.\scripts\demo\start-internet-demo.ps1` | Temporary authenticated internet demo |
| `.\scripts\demo\stop-internet-demo.ps1` | Stop and validate the temporary tunnel |

Each launcher preserves the existing `threatlens-batch7` Compose project and validates the required source lineage before operating.
