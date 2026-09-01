$ErrorActionPreference = "Stop"
Push-Location frontend
try {
    if (Test-Path node_modules) { Remove-Item -Recurse -Force node_modules }
    if (Test-Path package-lock.json) {
        npm ci
    }
    else {
        npm install
    }
    if ($LASTEXITCODE -ne 0) { throw "npm dependency installation failed" }
    npm run typecheck
    if ($LASTEXITCODE -ne 0) { throw "TypeScript typecheck failed" }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "Vite production build failed" }
    npm audit --audit-level=high
    if ($LASTEXITCODE -ne 0) { throw "npm high/critical vulnerability audit failed" }
    Write-Host "ThreatLens AI v0.12 frontend gate: PASS" -ForegroundColor Green
}
finally { Pop-Location }
