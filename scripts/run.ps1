$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

.\.venv\Scripts\Activate.ps1
alembic upgrade head
python -m scripts.bootstrap_security

$apiHost = if ($env:THREATLENS_API_HOST) { $env:THREATLENS_API_HOST } else { "127.0.0.1" }
$apiPort = if ($env:THREATLENS_API_PORT) { $env:THREATLENS_API_PORT } else { "8000" }
$env:THREATLENS_API_URL = "http://${apiHost}:${apiPort}"

$apiProcess = Start-Process `
    -FilePath (Get-Command python).Source `
    -ArgumentList @(
        "-m", "uvicorn", "api.main:app",
        "--host", $apiHost,
        "--port", $apiPort
    ) `
    -PassThru `
    -NoNewWindow

try {
    $ready = $false
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            $response = Invoke-RestMethod `
                -Uri "http://${apiHost}:${apiPort}/api/v1/health/ready" `
                -TimeoutSec 2
            if ($response.status -eq "ready") {
                $ready = $true
                break
            }
        }
        catch {
            if ($apiProcess.HasExited) {
                throw "ThreatLens FastAPI process exited before becoming ready."
            }
        }
    }
    if (-not $ready) {
        throw "ThreatLens FastAPI did not become ready within 20 seconds."
    }
    Write-Host "ThreatLens FastAPI ready at http://${apiHost}:${apiPort}" -ForegroundColor Green
    python -m streamlit run app/main.py `
        --server.address 127.0.0.1 `
        --client.showErrorDetails none `
        --server.enableXsrfProtection true `
        --server.enableCORS true
}
finally {
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
