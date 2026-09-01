param(
    [int]$FrontendPort = 5173,
    [int[]]$BackendCandidates = @(18080, 18081, 18082, 18765, 18888, 19000, 20080)
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$activate = Join-Path $projectRoot ".venv\Scripts\Activate.ps1"
$frontend = Join-Path $projectRoot "frontend"

if (-not (Test-Path $python)) { throw "Run INSTALL_THREATLENS_V012_AND_VERIFY.ps1 first." }
if (-not (Test-Path (Join-Path $frontend "node_modules\.bin\vite.cmd"))) { throw "Frontend dependencies are missing. Run the full installer/verification first." }
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { throw "Ollama is required for full local ThreatLens UAT." }

try {
    Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 5 | Out-Null
}
catch {
    throw "Ollama is not reachable on http://127.0.0.1:11434. Start Ollama and rerun."
}

$portProbe = @'
import socket, sys
for raw in sys.argv[1:]:
    port = int(raw)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    raise SystemExit(0)
raise SystemExit(2)
'@

$probeArgs = @("-") + @($BackendCandidates | ForEach-Object { "$_" })
$backendPort = ($portProbe | & $python @probeArgs).Trim()
if ($LASTEXITCODE -ne 0 -or -not $backendPort) {
    throw "No safe backend port was available from: $($BackendCandidates -join ', ')"
}

$oldFrontendListeners = @(Get-NetTCPConnection -LocalPort $FrontendPort -State Listen -ErrorAction SilentlyContinue)
foreach ($listener in $oldFrontendListeners) {
    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
    if ($processInfo -and ($processInfo.Name -eq "node.exe" -or $processInfo.CommandLine -match "vite")) {
        Stop-Process -Id $processInfo.ProcessId -Force -ErrorAction SilentlyContinue
    }
    elseif ($processInfo) {
        throw "Frontend port $FrontendPort is occupied by non-Vite process PID $($processInfo.ProcessId): $($processInfo.CommandLine)"
    }
}

$apiUrl = "http://127.0.0.1:$backendPort"
$webUrl = "http://127.0.0.1:$FrontendPort"

$apiScript = Join-Path $env:TEMP "ThreatLens_v012_api_uat.ps1"
@"
`$ErrorActionPreference = "Stop"
Set-Location "$projectRoot"
. "$activate"
`$env:THREATLENS_API_HOST = "127.0.0.1"
`$env:THREATLENS_API_PORT = "$backendPort"
`$env:THREATLENS_ALLOWED_ORIGINS = "$webUrl,http://localhost:$FrontendPort"
`$env:THREATLENS_TRUSTED_HOSTS = "127.0.0.1,localhost"
`$env:THREATLENS_RAG_STANDARD_LLM_MODEL = "qwen3.5:4b"
`$env:THREATLENS_RAG_LLM_MODEL = "qwen3.5:4b"
`$env:THREATLENS_RAG_DEEP_LLM_MODEL = "qwen3.5:9b"
`$env:THREATLENS_RAG_EMBEDDING_MODEL = "qwen3-embedding:0.6b"
Write-Host "ThreatLens FastAPI UAT: $apiUrl" -ForegroundColor Green
& ".\scripts\run_api.ps1"
"@ | Set-Content -Path $apiScript -Encoding UTF8

Start-Process powershell.exe -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-File", $apiScript)

$ready = $false
for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 1
    try {
        $health = Invoke-RestMethod -Uri "$apiUrl/api/v1/health/ready" -TimeoutSec 2
        if ($health.status -eq "ready") { $ready = $true; break }
    }
    catch {}
}
if (-not $ready) { throw "FastAPI did not become ready at $apiUrl. Inspect the API window." }

$cmd = "cd /d `"$frontend`" && set `"VITE_THREATLENS_API_URL=$apiUrl`" && `".\node_modules\.bin\vite.cmd`" . --host 127.0.0.1 --port $FrontendPort --strictPort"
Start-Process cmd.exe -ArgumentList "/k", $cmd

$frontendReady = $false
for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $response = Invoke-WebRequest -Uri "$webUrl/" -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200 -and $response.Content -match 'id="root"') { $frontendReady = $true; break }
    }
    catch {}
}
if (-not $frontendReady) { throw "React/Vite did not become ready at $webUrl. Inspect the Vite window." }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "THREATLENS AI v0.12 LOCAL UAT READY" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Frontend: $webUrl" -ForegroundColor Cyan
Write-Host "Backend : $apiUrl" -ForegroundColor Cyan
Write-Host "Ollama  : http://127.0.0.1:11434" -ForegroundColor Cyan
Write-Host ""
Write-Host "Keep the API and Vite windows open during UAT." -ForegroundColor Yellow
Start-Process $webUrl
