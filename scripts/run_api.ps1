$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

.\.venv\Scripts\Activate.ps1
alembic upgrade head
python -m scripts.bootstrap_security

$hostAddress = if ($env:THREATLENS_API_HOST) { $env:THREATLENS_API_HOST } else { "127.0.0.1" }
$port = if ($env:THREATLENS_API_PORT) { $env:THREATLENS_API_PORT } else { "8000" }

python -m uvicorn api.main:app --host $hostAddress --port $port
