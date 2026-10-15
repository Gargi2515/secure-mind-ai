$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontendPath = Join-Path $projectRoot 'frontend'
Set-Location $frontendPath

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'Node.js/npm is not installed. Install Node.js, then reopen VS Code.'
}

if (-not (Test-Path 'node_modules')) {
    Write-Host '[SecureMind AI] Installing frontend dependencies (first run may take a few minutes)...' -ForegroundColor Cyan
    npm install
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
}

Write-Host '[SecureMind AI] Starting frontend. Open http://127.0.0.1:5173' -ForegroundColor Green
npm run dev
