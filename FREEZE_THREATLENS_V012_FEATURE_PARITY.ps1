param(
    [string]$OutputDirectory = "",
    [switch]$SkipFullVerification
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Split-Path $projectRoot -Parent
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$uatReports = @(Get-ChildItem (Join-Path $projectRoot "data\uat\feature-parity-uat-*.json") -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
if ($uatReports.Count -eq 0) {
    throw "No feature-parity UAT report exists. Run RECORD_FEATURE_PARITY_UAT.ps1 and obtain PASS first."
}
$uat = Get-Content $uatReports[0].FullName -Raw | ConvertFrom-Json
if ($uat.status -ne "passed") {
    throw "Latest feature-parity UAT report is not PASS: $($uatReports[0].FullName)"
}

if (-not $SkipFullVerification) {
    $env:THREATLENS_REQUIRE_ONLINE_DEPENDENCY_AUDIT = "1"
    $env:THREATLENS_REQUIRE_RAG_READY = "1"
    & .\scripts\verify.ps1
    if ($LASTEXITCODE -ne 0) { throw "Full ThreatLens verification failed; freeze aborted." }
}

python -m scripts.generate_release_manifest
if ($LASTEXITCODE -ne 0) { throw "Release manifest regeneration failed." }

$archive = Join-Path $OutputDirectory "ThreatLensAI_v0.12_FULL_FEATURE_PARITY_VERIFIED_SOURCE.zip"
$report = Join-Path $OutputDirectory "ThreatLensAI_v0.12_FULL_FEATURE_PARITY_FREEZE_REPORT.json"
python -m scripts.build_source_archive $archive --report $report
if ($LASTEXITCODE -ne 0) { throw "Source archive build/verification failed." }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "THREATLENS AI v0.12 FEATURE-PARITY FREEZE: PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "ZIP:    $archive"
Write-Host "REPORT: $report"
Write-Host ""
Write-Host "This freezes the locally verified feature-parity source only. Production immutability still requires PostgreSQL/pgvector staging, hosted inference, Render/Vercel live UAT and post-deployment security checks." -ForegroundColor Yellow
