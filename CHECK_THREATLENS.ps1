param(
    [switch]$RequireObservability,
    [switch]$RequireAI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Project ".env.batch7.local"
$Compose = Join-Path $Project "compose.batch7.yml"
$ProjectName = "threatlens-batch7"

function Invoke-Probe {
    param(
        [string]$Name,
        [string]$Url,
        [switch]$Json
    )
    try {
        if ($Json) {
            $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 8
            return [pscustomobject]@{ Name=$Name; Ok=$true; Detail=$response }
        }
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -Method Get -TimeoutSec 8
        return [pscustomobject]@{
            Name=$Name
            Ok=($response.StatusCode -eq 200)
            Detail="HTTP $($response.StatusCode)"
        }
    }
    catch {
        return [pscustomobject]@{ Name=$Name; Ok=$false; Detail=$_.Exception.Message }
    }
}

function Get-ServiceState {
    param([string]$Service)

    $dockerArgs = @(
        "compose","-p",$ProjectName,
        "--profile","observability",
        "--env-file",$EnvFile,
        "-f",$Compose,
        "ps","-q",$Service
    )
    $id = ((& docker.exe @dockerArgs 2>$null | Out-String).Trim())
    if (-not $id) {
        return [pscustomobject]@{
            Service=$Service
            Running=$false
            Healthy=$false
            State="missing"
            Id=""
        }
    }

    $state = ((& docker.exe inspect --format "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $id 2>$null | Out-String).Trim())
    if ($LASTEXITCODE -ne 0 -or -not $state) {
        return [pscustomobject]@{
            Service=$Service
            Running=$false
            Healthy=$false
            State="inspect_failed"
            Id=$id
        }
    }

    $parts = $state.Split("|")
    $running = ($parts[0] -eq "running")
    $health = if ($parts.Count -gt 1) { $parts[1] } else { "none" }
    $healthy = $running -and ($health -in @("healthy","none"))

    return [pscustomobject]@{
        Service=$Service
        Running=$running
        Healthy=$healthy
        State="$($parts[0])/$health"
        Id=$id
    }
}

if (-not (Test-Path -LiteralPath $EnvFile)) { throw "Missing runtime env: $EnvFile" }
if (-not (Test-Path -LiteralPath $Compose)) { throw "Missing compose file: $Compose" }

& cmd.exe /d /c "docker info >nul 2>nul"
if ($LASTEXITCODE -ne 0) { throw "Docker engine is not ready." }

$failed = New-Object System.Collections.Generic.List[string]
$core = @("postgres","redis","api","worker","frontend")
$obs = @("prometheus","grafana","postgres_exporter","redis_exporter")
$states = @{}

Write-Host ""
Write-Host "ThreatLens local runtime health" -ForegroundColor Cyan
Write-Host ("-" * 62)

foreach ($service in $core) {
    $state = Get-ServiceState -Service $service
    $states[$service] = $state
    if ($state.Healthy) {
        Write-Host ("[OK]   {0,-20} {1}" -f $service,$state.State) -ForegroundColor Green
    } else {
        Write-Host ("[FAIL] {0,-20} {1}" -f $service,$state.State) -ForegroundColor Red
        $failed.Add("container:$service") | Out-Null
    }
}

foreach ($service in $obs) {
    $state = Get-ServiceState -Service $service
    $states[$service] = $state
    if ($state.Healthy) {
        Write-Host ("[OK]   {0,-20} {1}" -f $service,$state.State) -ForegroundColor Green
    } elseif ($RequireObservability) {
        Write-Host ("[FAIL] {0,-20} {1}" -f $service,$state.State) -ForegroundColor Red
        $failed.Add("container:$service") | Out-Null
    } else {
        Write-Host ("[INFO] {0,-20} {1}" -f $service,$state.State) -ForegroundColor DarkGray
    }
}

$frontend = Invoke-Probe -Name "frontend" -Url "http://127.0.0.1:8080"
$live = Invoke-Probe -Name "api-live" -Url "http://127.0.0.1:8080/api/v1/health/live" -Json
$ready = Invoke-Probe -Name "api-ready" -Url "http://127.0.0.1:8080/api/v1/health/ready" -Json

foreach ($probe in @($frontend,$live,$ready)) {
    if ($probe.Ok) {
        Write-Host "[OK]   endpoint $($probe.Name)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] endpoint $($probe.Name): $($probe.Detail)" -ForegroundColor Red
        $failed.Add("endpoint:$($probe.Name)") | Out-Null
    }
}

if ($ready.Ok) {
    if ($ready.Detail.status -ne "ready") {
        Write-Host "[FAIL] API readiness status is '$($ready.Detail.status)'." -ForegroundColor Red
        $failed.Add("api:not_ready") | Out-Null
    }
    if ($ready.Detail.database -ne "reachable") {
        Write-Host "[FAIL] Database is not reachable according to readiness payload." -ForegroundColor Red
        $failed.Add("database:not_reachable") | Out-Null
    }
    if ($ready.Detail.async_jobs.enabled) {
        if (-not $ready.Detail.async_jobs.reachable) {
            Write-Host "[FAIL] Redis is not reachable according to readiness payload." -ForegroundColor Red
            $failed.Add("redis:not_reachable") | Out-Null
        }
        if ([int]$ready.Detail.async_jobs.workers -lt 1) {
            Write-Host "[FAIL] No active AI worker is registered." -ForegroundColor Red
            $failed.Add("worker:none") | Out-Null
        }
    }
}

if ($RequireObservability) {
    foreach ($item in @(
        @{Name="prometheus";Url="http://127.0.0.1:9090/-/ready"},
        @{Name="grafana";Url="http://127.0.0.1:3000/api/health"}
    )) {
        $probe = Invoke-Probe -Name $item.Name -Url $item.Url
        if ($probe.Ok) {
            Write-Host "[OK]   endpoint $($probe.Name)" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] endpoint $($probe.Name): $($probe.Detail)" -ForegroundColor Red
            $failed.Add("endpoint:$($probe.Name)") | Out-Null
        }
    }
}

$ollama = Invoke-Probe -Name "ollama" -Url "http://127.0.0.1:11434/api/tags"
if ($ollama.Ok) {
    Write-Host "[OK]   endpoint ollama" -ForegroundColor Green
} elseif ($RequireAI) {
    Write-Host "[FAIL] endpoint ollama: $($ollama.Detail)" -ForegroundColor Red
    $failed.Add("endpoint:ollama") | Out-Null
} else {
    Write-Host "[WARN] Ollama unavailable; deterministic SOC remains usable, AI is degraded." -ForegroundColor Yellow
}

if ($RequireAI -and $ollama.Ok) {
    if (-not $states.ContainsKey("api") -or -not $states["api"].Healthy -or -not $states["api"].Id) {
        Write-Host "[FAIL] Cannot execute RAG readiness smoke because API container is unavailable." -ForegroundColor Red
        $failed.Add("rag:api_unavailable") | Out-Null
    }
    else {
        Write-Host ""
        Write-Host "ThreatLens grounded-RAG live readiness" -ForegroundColor Cyan
        Write-Host ("-" * 62)
        $apiId = $states["api"].Id
        $command = "docker exec $apiId python -m scripts.verify_rag_runtime --require-ready 2>&1"
        $ragOutput = @(& cmd.exe /d /c $command)
        $ragExit = $LASTEXITCODE
        if ($ragOutput) { $ragOutput | ForEach-Object { Write-Host $_ } }

        if ($ragExit -eq 0) {
            Write-Host "[OK]   grounded RAG health + embedding + retrieval + structured generation" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] grounded RAG live readiness verification failed." -ForegroundColor Red
            $failed.Add("rag:live_smoke") | Out-Null
        }
    }
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "THREATLENS RUNTIME HEALTH: FAIL" -ForegroundColor Red
    Write-Host ("Failures: " + ($failed -join ", "))
    exit 1
}

Write-Host ""
Write-Host "THREATLENS RUNTIME HEALTH: PASS" -ForegroundColor Green
exit 0