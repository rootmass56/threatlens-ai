$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $PSScriptRoot
Set-Location $project

function New-HexSecret([int]$Bytes) {
    if ($Bytes -lt 1) {
        throw "Secret byte length must be positive."
    }

    $data = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $rng.GetBytes($data)
    }
    finally {
        $rng.Dispose()
    }

    return -join ($data | ForEach-Object { $_.ToString("x2") })
}

$out = Join-Path $project ".env.batch5.local"

if (Test-Path $out) {
    Write-Host "Batch 5 environment already exists: $out" -ForegroundColor Yellow
    Write-Host "Existing secrets were preserved. Delete the file explicitly only when rotating secrets."
    exit 0
}

$postgres = New-HexSecret 24
$redis = New-HexSecret 24
$jwt = New-HexSecret 48
$admin = "Tl5!" + (New-HexSecret 18)

$content = @"
THREATLENS_POSTGRES_PASSWORD=$postgres
THREATLENS_REDIS_PASSWORD=$redis
THREATLENS_JWT_SECRET=$jwt
THREATLENS_BOOTSTRAP_ADMIN_PASSWORD=$admin
THREATLENS_OLLAMA_URL=http://host.docker.internal:11434
THREATLENS_OLLAMA_API_KEY=
"@

# Write UTF-8 without BOM so Docker Compose receives a clean first variable name.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($out, $content, $utf8NoBom)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "THREATLENS BATCH 5 LOCAL SECRETS CREATED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Environment : $out"
Write-Host "Admin user  : admin"
Write-Host ""
Write-Host "The administrator password is stored only in .env.batch5.local." -ForegroundColor Yellow
Write-Host "Do not share, upload or commit that file." -ForegroundColor Yellow
