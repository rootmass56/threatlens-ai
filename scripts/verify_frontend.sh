#!/usr/bin/env sh
set -eu
cd frontend
if [ -f package-lock.json ]; then npm ci; else npm install; fi
npm run typecheck
npm run build
npm audit --audit-level=high
echo "ThreatLens AI v0.12 frontend gate: PASS"
