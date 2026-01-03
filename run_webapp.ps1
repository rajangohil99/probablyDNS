$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Error "Virtual environment Python not found at $python. Run 'python -m venv .venv' and install requirements first."
}

Set-Location $root
& $python -m uvicorn dns_analyzer.webapp:app --host 127.0.0.1 --port 8000
