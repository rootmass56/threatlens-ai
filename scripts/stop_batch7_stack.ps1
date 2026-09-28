param([switch]$RemoveVolumes)
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $project ".env.batch7.local"
$compose = Join-Path $project "compose.yaml"
if (-not (Test-Path -LiteralPath $envFile)) { throw ".env.batch7.local is missing." }
$args = @("compose","--profile","observability","--profile","syslog","--env-file",$envFile,"-f",$compose,"down")
if ($RemoveVolumes) { $args += "-v" }
& docker.exe @args
if ($LASTEXITCODE -ne 0) { throw "Batch-7 Docker shutdown failed." }
