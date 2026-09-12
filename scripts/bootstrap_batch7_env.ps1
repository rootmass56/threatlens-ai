param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$out = Join-Path $project ".env.batch7.local"

if ((Test-Path -LiteralPath $out) -and -not $Force) {
    Write-Host "Batch-7 environment already exists: $out" -ForegroundColor Green
    exit 0
}

function New-Secret([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buffer).Replace("+","A").Replace("/","B").Replace("=","")
}

$ollama = "http://host.docker.internal:11434"
$batch6 = Join-Path $project ".env.batch6.local"
if (Test-Path -LiteralPath $batch6) {
    $line = Get-Content -LiteralPath $batch6 | Where-Object { $_ -like "THREATLENS_OLLAMA_URL=*" } | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace([string]$line)) {
        $idx = $line.IndexOf("=")
        if ($idx -ge 0) { $ollama = $line.Substring($idx + 1).Trim() }
    }
}

$lines = @(
    "# ThreatLens AI v0.14.0 / Batch 7 local secrets. NEVER COMMIT.",
    "THREATLENS_POSTGRES_PASSWORD=$(New-Secret 32)",
    "THREATLENS_REDIS_PASSWORD=$(New-Secret 32)",
    "THREATLENS_JWT_SECRET=$(New-Secret 48)",
    "THREATLENS_BOOTSTRAP_ADMIN_PASSWORD=$(New-Secret 24)",
    "THREATLENS_GRAFANA_ADMIN_PASSWORD=$(New-Secret 24)",
    "THREATLENS_OLLAMA_URL=$ollama",
    "THREATLENS_OLLAMA_API_KEY=",
    "THREATLENS_SYSLOG_INGEST_KEY="
)

[System.IO.File]::WriteAllLines($out, $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "BATCH 7 LOCAL ENVIRONMENT CREATED: $out" -ForegroundColor Green
Write-Host "Secrets were written only to the ignored local environment file and were not printed." -ForegroundColor Yellow
