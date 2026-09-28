param(
    [switch]$NoBrowser,
    [string]$ContextOut = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$ProjectName = "threatlens-batch7"
$RequiredBranch = "phase5/golden-demo-mode"
$RequiredAncestor = "bc94a10834720cbb576fa340b9d7a1767b3d6c43"

$Compose = Join-Path $Project "compose.yaml"
$EnvFile = Join-Path $Project ".env.batch7.local"
$HealthChecker = Join-Path $Project "CHECK_THREATLENS.ps1"
$Resolver = Join-Path $Project "scripts\golden_demo_context.py"

$TempRoot = Join-Path $env:TEMP ("threatlens-golden-demo-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
$script:NativeCounter = 0

function Fail {
    param([Parameter(Mandatory=$true)][string]$Message)
    throw $Message
}

function Invoke-Native {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$Label,
        [switch]$EchoStdout,
        [switch]$AllowFailure
    )

    if ($ArgumentList.Length -lt 1) {
        Fail -Message ("Native argument list empty for {0}." -f $Label)
    }

    $script:NativeCounter++
    $stdoutPath = Join-Path $TempRoot ("{0:D3}.stdout.txt" -f $script:NativeCounter)
    $stderrPath = Join-Path $TempRoot ("{0:D3}.stderr.txt" -f $script:NativeCounter)

    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $stdout = if (Test-Path -LiteralPath $stdoutPath) {
        [IO.File]::ReadAllText($stdoutPath)
    } else { "" }

    $stderr = if (Test-Path -LiteralPath $stderrPath) {
        [IO.File]::ReadAllText($stderrPath)
    } else { "" }

    if ($EchoStdout -and -not [string]::IsNullOrWhiteSpace($stdout)) {
        Write-Host $stdout.TrimEnd()
    }

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray
    }

    if (-not $AllowFailure -and [int]$process.ExitCode -ne 0) {
        Fail -Message ("{0} failed with native exit code {1}." -f $Label,$process.ExitCode)
    }

    return [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Invoke-FullHealth {
    param([switch]$AllowFailure)

    return Invoke-Native `
        -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy","Bypass",
            "-File",$HealthChecker,
            "-RequireObservability",
            "-RequireAI"
        ) `
        -Label "full-health" `
        -AllowFailure:$AllowFailure `
        -EchoStdout
}

function Wait-ApiReady {
    param([int]$TimeoutSeconds = 300)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        try {
            $ready = Invoke-RestMethod `
                -Uri "http://127.0.0.1:8080/api/v1/health/ready" `
                -TimeoutSec 8

            $front = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri "http://127.0.0.1:8080/" `
                -TimeoutSec 8

            if (
                [string]$ready.status -eq "ready" -and
                [string]$ready.database -eq "reachable" -and
                [int]$front.StatusCode -eq 200
            ) {
                return
            }
        }
        catch {}

        Start-Sleep -Seconds 4
    }
    while ((Get-Date) -lt $deadline)

    Fail -Message "ThreatLens did not reach API/frontend ready state within 300 seconds."
}

try {
    Write-Host ""
    Write-Host ("=" * 92) -ForegroundColor Cyan
    Write-Host "THREATLENS AI - GOLDEN DEMO MODE" -ForegroundColor Cyan
    Write-Host ("=" * 92) -ForegroundColor Cyan

    foreach ($required in @($Compose,$EnvFile,$HealthChecker,$Resolver)) {
        if (-not (Test-Path -LiteralPath $required)) {
            Fail -Message ("Required demo dependency missing: {0}" -f $required)
        }
    }

    Write-Host "[1/5] Validate Golden Demo source lineage" -ForegroundColor Yellow

    $branchRun = Invoke-Native `
        -FilePath "git.exe" `
        -ArgumentList @("-C",$Project,"branch","--show-current") `
        -Label "branch"

    $branch = ([string]$branchRun.Stdout).Trim()
    if ($branch -ne $RequiredBranch) {
        Fail -Message ("Golden Demo requires branch {0}; found {1}." -f $RequiredBranch,$branch)
    }

    $ancestorRun = Invoke-Native `
        -FilePath "git.exe" `
        -ArgumentList @("-C",$Project,"merge-base","--is-ancestor",$RequiredAncestor,"HEAD") `
        -Label "lineage" `
        -AllowFailure

    if ([int]$ancestorRun.ExitCode -ne 0) {
        Fail -Message "Current HEAD is not descended from the accepted Phase5B Golden Demo foundation."
    }

    $statusRun = Invoke-Native `
        -FilePath "git.exe" `
        -ArgumentList @("-C",$Project,"status","--porcelain=v1","--untracked-files=all") `
        -Label "worktree"

    if (-not [string]::IsNullOrWhiteSpace([string]$statusRun.Stdout)) {
        Write-Host "[WARN] Worktree has local changes. Formal acceptance requires a clean tree." -ForegroundColor Yellow
    }
    else {
        Write-Host "[OK] Source lineage valid; worktree clean." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[2/5] Start or reuse local ThreatLens services non-destructively" -ForegroundColor Yellow

    $initialHealth = Invoke-FullHealth -AllowFailure

    if ([int]$initialHealth.ExitCode -eq 0) {
        Write-Host "[OK] Existing runtime already healthy; no Compose start required." -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Runtime is not fully demo-ready. Starting/reusing Compose services without build/reset..." -ForegroundColor Cyan

        $null = Invoke-Native `
            -FilePath "docker.exe" `
            -ArgumentList @(
                "compose",
                "--project-directory",$Project,
                "-p",$ProjectName,
                "--profile","observability",
                "--env-file",$EnvFile,
                "-f",$Compose,
                "up","-d","--no-build"
            ) `
            -Label "compose-up" `
            -EchoStdout

        Wait-ApiReady -TimeoutSeconds 300
    }

    Write-Host ""
    Write-Host "[3/5] Require runtime / observability / Ollama / grounded-RAG readiness" -ForegroundColor Yellow

    $finalHealth = Invoke-FullHealth

    if ([int]$finalHealth.ExitCode -ne 0) {
        Fail -Message "ThreatLens full health check did not PASS."
    }

    if (-not ([string]$finalHealth.Stdout).Contains("THREATLENS RUNTIME HEALTH: PASS")) {
        Fail -Message "ThreatLens health checker did not emit the expected PASS marker."
    }

    Write-Host "[OK] Complete ThreatLens runtime is demo-ready." -ForegroundColor Green

    Write-Host ""
    Write-Host "[4/5] Resolve immutable Golden Demo SOC context" -ForegroundColor Yellow

    $mount = "{0}:/workspace:ro" -f $Project

    $resolverRun = Invoke-Native `
        -FilePath "docker.exe" `
        -ArgumentList @(
            "compose",
            "--project-directory",$Project,
            "-p",$ProjectName,
            "--profile","observability",
            "--env-file",$EnvFile,
            "-f",$Compose,
            "run","--rm","--no-deps","-T",
            "-v",$mount,
            "-e","PYTHONPATH=/workspace",
            "api",
            "python","/workspace/scripts/golden_demo_context.py"
        ) `
        -Label "resolver"

    $resolved = ([string]$resolverRun.Stdout).Trim() | ConvertFrom-Json

    if ($resolved.status -ne "PASS") {
        Fail -Message "Golden Demo context resolver did not PASS."
    }

    $analysis = [string]$resolved.context.analysis_uuid
    $incident = [string]$resolved.context.incident_uuid
    $base = "http://127.0.0.1:8080"
    $query = "analysis=$analysis&incident=$incident"

    $urls = [ordered]@{
        overview = "$base/#/overview?$query"
        current_analysis = "$base/#/current?$query"
        incident_queue = "$base/#/incidents?$query"
        case_details = "$base/#/case?$query"
        ai_investigation = "$base/#/assistant?$query"
        attack_graph = "$base/#/graph?$query"
        mitre_attack = "$base/#/attack?$query"
        threat_intelligence = "$base/#/intel?$query"
        threat_hunting = "$base/#/hunts?$query"
        case_operations = "$base/#/caseops?$query"
        audit_trail = "$base/#/audit?$query"
        system_health = "$base/#/system?$query"
    }

    $context = [ordered]@{
        status = "PASS"
        analysis_uuid = $analysis
        incident_uuid = $incident
        incident_title = [string]$resolved.context.incident_title
        events = [int]$resolved.context.events
        alerts = [int]$resolved.context.alerts
        incidents = [int]$resolved.context.incidents
        quarantined = [int]$resolved.context.quarantined
        capabilities = [ordered]@{
            notes = [int]$resolved.context.notes
            evidence = [int]$resolved.context.evidence
            custody_events = [int]$resolved.context.custody_events
            rag_queries = [int]$resolved.context.rag_queries
            graph_snapshots = [int]$resolved.context.graph_snapshots
            threat_intel_hits = [int]$resolved.context.threat_intel_hits
            saved_hunts = [int]$resolved.context.saved_hunts
            hunt_executions = [int]$resolved.context.hunt_executions
            audit_records = [int]$resolved.context.audit_records
        }
        urls = $urls
    }

    if (-not [string]::IsNullOrWhiteSpace($ContextOut)) {
        $parent = Split-Path -Parent $ContextOut
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }

        [IO.File]::WriteAllText(
            $ContextOut,
            ($context | ConvertTo-Json -Depth 30),
            (New-Object Text.UTF8Encoding($false))
        )
    }

    Write-Host "[OK] Golden Demo context resolved." -ForegroundColor Green
    Write-Host ""
    Write-Host ("Reference analysis  : {0}" -f $analysis)
    Write-Host ("Integrated incident : {0}" -f $incident)
    Write-Host ("SOC storyline       : {0} events / {1} alerts / {2} incidents / {3} quarantine" -f $context.events,$context.alerts,$context.incidents,$context.quarantined)

    Write-Host ""
    Write-Host "[5/5] Golden Demo is ready" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recruiter demo order:" -ForegroundColor Cyan
    Write-Host "  1. Overview"
    Write-Host "  2. Current Analysis"
    Write-Host "  3. Incident Queue"
    Write-Host "  4. Case Details"
    Write-Host "  5. MITRE ATT&CK"
    Write-Host "  6. Attack Graph"
    Write-Host "  7. Threat Intelligence"
    Write-Host "  8. Threat Hunting"
    Write-Host "  9. Case Operations / evidence / custody"
    Write-Host " 10. AI Investigation / grounded citations"
    Write-Host " 11. Audit Trail"
    Write-Host " 12. System Health"
    Write-Host ""
    Write-Host ("Overview URL         : {0}" -f $urls.overview)
    Write-Host ("Case URL             : {0}" -f $urls.case_details)
    Write-Host ("AI Investigation URL : {0}" -f $urls.ai_investigation)
    Write-Host ("System Health URL    : {0}" -f $urls.system_health)
    Write-Host ""
    Write-Host "Authentication remains enabled. Sign in with your existing authorized ThreatLens analyst account." -ForegroundColor Yellow
    Write-Host "No credential is stored in this launcher." -ForegroundColor DarkGray

    if (-not $NoBrowser) {
        Start-Process $urls.overview | Out-Null
        Write-Host "[OK] Browser opened to the Golden Demo Overview." -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Browser launch suppressed by -NoBrowser." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "THREATLENS GOLDEN DEMO: READY" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host ""
    Write-Host "THREATLENS GOLDEN DEMO: NOT READY" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
finally {
    try {
        if (Test-Path -LiteralPath $TempRoot) {
            Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}
