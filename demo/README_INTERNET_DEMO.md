# ThreatLens AI — Secure Temporary Internet Demo

This mode exposes the authenticated ThreatLens operational console only for a supervised recruiter/interviewer demonstration.

## Security model

The only public origin is a temporary Cloudflare Quick Tunnel URL pointing to `http://127.0.0.1:8080`. Nginx remains the application boundary and proxies only `/api/*` to the Docker-private API service.

The following remain private and must never receive public host mappings: PostgreSQL, Redis, API port 10000, Ollama, Prometheus, Grafana, exporters, Docker daemon, and `/internal/metrics`.

ThreatLens authentication and RBAC remain enabled. No username, password, token, API key, or tunnel credential is stored in source, launchers, or receipts.

## Quick Tunnel lifecycle

Quick Tunnels are for temporary testing/demo use. Their `*.trycloudflare.com` hostname changes when the tunnel process restarts. Do not use the URL as permanent hosting.

Before the first demo session, install the official Cloudflare Tunnel client if `cloudflared` is not already available:

```powershell
winget install --id Cloudflare.cloudflared -e
```

Open a new PowerShell window after installation if the executable is not immediately found.

Start the supervised internet demo:

```powershell
.\scripts\demo\start-internet-demo.ps1
```

Stop public exposure immediately after the demonstration:

```powershell
.\scripts\demo\stop-internet-demo.ps1
```

The start launcher refuses to run a Quick Tunnel if `%USERPROFILE%\.cloudflared\config.yml` or `config.yaml` exists. It never reads, renames, overwrites, or deletes those files.

## Demo rules

Use the existing authorized ThreatLens account. Do not share credentials in chat, source files, screenshots, terminals, or presentation assets. Log out when the demonstration is over, close the demo browser, and run the stop launcher.

The permanent sanitized public portfolio remains separate:

`https://threatlens-ai-showcase.pages.dev`
