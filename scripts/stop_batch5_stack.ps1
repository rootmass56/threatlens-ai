
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$envFile = Join-Path $project ".env.batch5.local"
if (-not (Test-Path $envFile)) { throw ".env.batch5.local does not exist." }
docker compose --env-file $envFile -f compose.batch5.yml down
