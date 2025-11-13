# FastAPI dev server runner
# Usage: ./run.ps1

$ErrorActionPreference = "Stop"

# Prefer local venv python
$python = Join-Path $PSScriptRoot ".venv311\Scripts\python.exe"
if (-not (Test-Path $python)) {
  Write-Host "Virtual environment .venv311 not found. Falling back to system Python..." -ForegroundColor Yellow
  $python = "python"
}

# Start server with auto-reload
& $python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
