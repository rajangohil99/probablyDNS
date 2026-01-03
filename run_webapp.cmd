@echo off
set ROOT=%~dp0
set PYTHON=%ROOT%.venv\Scripts\python.exe

if not exist "%PYTHON%" (
  echo Virtual environment Python not found at "%PYTHON%".
  echo Run "python -m venv .venv" and install requirements first.
  exit /b 1
)

cd /d "%ROOT%"
"%PYTHON%" -m uvicorn dns_analyzer.webapp:app --host 127.0.0.1 --port 8000
