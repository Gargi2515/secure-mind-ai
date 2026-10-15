$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendPath = Join-Path $projectRoot 'backend'
Set-Location $backendPath

if (-not (Test-Path '.venv\Scripts\python.exe')) {
    Write-Host '[SecureMind AI] Creating Python virtual environment...' -ForegroundColor Cyan
    python -m venv .venv
}

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host '[SecureMind AI] Created backend\.env for local demo login.' -ForegroundColor Cyan
}

$venvPython = Join-Path $backendPath '.venv\Scripts\python.exe'
Write-Host '[SecureMind AI] Installing backend requirements (first run may take a few minutes)...' -ForegroundColor Cyan
& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }

Write-Host '[SecureMind AI] Starting backend at http://127.0.0.1:8000' -ForegroundColor Green
Write-Host '[SecureMind AI] API docs: http://127.0.0.1:8000/docs' -ForegroundColor Green
& $venvPython -m uvicorn app.main:app --reload --port 8000
