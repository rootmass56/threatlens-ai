# Release metadata

This directory contains generated metadata for the current source lineage.

- `RELEASE_MANIFEST_v0.14.0.json` records the canonical SHA-256, size and content mode of every releasable source file.
- `python -m scripts.verify_release_manifest` verifies the checked-in manifest.
- `python -m scripts.generate_release_manifest` regenerates it after an intentional source-tree change.

Published immutable releases and their assets remain available through GitHub Releases. The `v1.0.0` tag is the accepted release snapshot; this directory describes the current post-release `main` source tree.
