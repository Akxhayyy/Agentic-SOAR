@echo off
TITLE SOAR CAPSULE RUNTIME
cd /d "%~dp0"
REM Quick start for an already-installed capsule (run_soar.bat does the full install).
echo [1/2] Enforcing VRAM constraints (one resident model)...
set OLLAMA_MAX_LOADED_MODELS=1
set OLLAMA_NUM_PARALLEL=1
set OLLAMA_KEEP_ALIVE=300s
set OLLAMA_HOST=127.0.0.1:11434
set DO_NOT_TRACK=1
if not exist "frontend\dist\index.html" echo [WARN] Web UI not built - run run_soar.bat once, or: cd frontend ^&^& npm ci ^&^& npm run build
echo [2/2] Launching backend + UI on http://127.0.0.1:8000 ...
start "SOAR Capsule" cmd /k "call venv\Scripts\activate.bat && uvicorn main:app --host 127.0.0.1 --port 8000"
timeout /t 6 > nul
start "" http://127.0.0.1:8000
echo Launched. This window can be closed.
