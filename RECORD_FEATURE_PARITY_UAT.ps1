param(
    [string]$Analyst = $env:USERNAME
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$checks = @(
    "Authentication: valid login and safe invalid-login behavior",
    "Overview: persisted metrics, incident posture and RAG status",
    "Upload & Analyze: Linux/Windows/Sysmon/Suricata/Zeek multi-source ingestion",
    "Current Analysis: sources, events, alerts, incidents, timeline, quarantine and correlation",
    "Analysis History: persisted reload/search/export",
    "Incident Queue: lifecycle filtering/search/case navigation",
    "Case Details: alerts, events, entities, relationships and attack-graph evidence",
    "Workflow: assignment/status/priority changes obey RBAC/object rules",
    "Evidence + Notes: registry hashing/metadata and investigation notes persist/audit",
    "AI Standard: Qwen3.5:4b grounded response with valid citations",
    "AI Deep: Qwen3.5:9b grounded response with routing metadata",
    "AI Auto: routine->Standard and complex->Deep deterministic routing",
    "AI Safety: prompt-injection/secret-extraction request safely refused",
    "MITRE ATT&CK: catalogues, techniques, mappings, gaps, Navigator and sync authorization",
    "Detection Engineering: catalog, details, fixtures, validation, quality and profiles",
    "Connector Health: registry, coverage and safe diagnostics",
    "Reports: authorized PDF download and SHA-256 verification",
    "Audit Trail: recent workflow/note/RAG/admin actions visible under RBAC",
    "Administration: users, six-role RBAC, lifecycle actions, security status and protected OpenAPI",
    "System/RAG: model profiles, knowledge status and privileged reindex controls",
    "Session lifecycle: refresh rotation preserves session and logout revokes it",
    "Responsive layout: desktop, narrow/tablet and mobile behavior"
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "THREATLENS AI v0.12 - FEATURE-PARITY UAT RECORDER" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Enter P=pass, F=fail or S=skipped for each governed check." -ForegroundColor Yellow
Write-Host "A release-quality phase result requires every check to PASS." -ForegroundColor Yellow
Write-Host ""

$results = @()
for ($i = 0; $i -lt $checks.Count; $i++) {
    $label = $checks[$i]
    do {
        $answer = (Read-Host ("[{0:D2}/{1:D2}] {2} [P/F/S]" -f ($i + 1), $checks.Count, $label)).Trim().ToUpperInvariant()
    } while ($answer -notin @("P", "F", "S"))

    $status = switch ($answer) {
        "P" { "passed" }
        "F" { "failed" }
        default { "skipped" }
    }
    $notes = Read-Host "Optional evidence/notes (Enter to continue)"
    $results += [ordered]@{
        number = $i + 1
        check = $label
        status = $status
        notes = $notes
    }
}

$failed = @($results | Where-Object { $_.status -ne "passed" })
$overall = if ($failed.Count -eq 0) { "passed" } else { "failed" }
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$outputDir = Join-Path $projectRoot "data\uat"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$outputPath = Join-Path $outputDir "feature-parity-uat-$timestamp.json"

$payload = [ordered]@{
    product = "ThreatLens AI"
    release = "0.12.0"
    phase = "React full feature parity"
    analyst = $Analyst
    completed_utc = (Get-Date).ToUniversalTime().ToString("o")
    frontend = "React/Vite"
    total_checks = $checks.Count
    passed_checks = @($results | Where-Object { $_.status -eq "passed" }).Count
    nonpassing_checks = $failed.Count
    status = $overall
    results = $results
}

$payload | ConvertTo-Json -Depth 8 | Set-Content -Path $outputPath -Encoding UTF8

Write-Host ""
Write-Host "UAT report: $outputPath" -ForegroundColor Cyan
if ($overall -eq "passed") {
    Write-Host "THREATLENS FEATURE-PARITY UAT: PASS" -ForegroundColor Green
}
else {
    Write-Host "THREATLENS FEATURE-PARITY UAT: NOT PASSED" -ForegroundColor Red
    Write-Host "Resolve every failed/skipped item before deployment or phase freeze." -ForegroundColor Yellow
    exit 1
}
