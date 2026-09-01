$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project

function New-HexSecret([int]$Bytes) {
    if ($Bytes -lt 1) { throw "Secret byte length must be positive." }
    $data = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($data) } finally { $rng.Dispose() }
    return -join ($data | ForEach-Object { $_.ToString("x2") })
}

$out = Join-Path $project ".env.batch6.local"
if (Test-Path $out) {
    Write-Host "Batch 6 environment already exists: $out" -ForegroundColor Yellow
    Write-Host "Existing secrets were preserved. Delete the file explicitly only when rotating secrets."
    exit 0
}

$postgres = New-HexSecret 24
$redis = New-HexSecret 24
$jwt = New-HexSecret 48
$admin = "Tl6!" + (New-HexSecret 18)
$content = @"
THREATLENS_POSTGRES_PASSWORD=$postgres
THREATLENS_REDIS_PASSWORD=$redis
THREATLENS_JWT_SECRET=$jwt
THREATLENS_BOOTSTRAP_ADMIN_PASSWORD=$admin
THREATLENS_OLLAMA_URL=http://host.docker.internal:11434
THREATLENS_OLLAMA_API_KEY=
THREATLENS_SYSLOG_INGEST_KEY=
"@
[System.IO.File]::WriteAllText($out, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "BATCH 6 LOCAL ENVIRONMENT CREATED: $out" -ForegroundColor Green
Write-Host "Admin user: admin" -ForegroundColor Cyan
Write-Host "Admin password is stored only in the ignored local environment file." -ForegroundColor Yellow
