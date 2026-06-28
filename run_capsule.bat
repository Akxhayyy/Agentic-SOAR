@echo off
TITLE VSSC SOAR CAPSULE CORE RUNTIME
cd /d "%~dp0"
echo [1/3] Enforcing Specification VRAM Constraints...
set OLLAMA_MAX_LOADED_MODELS=1
set OLLAMA_NUM_PARALLEL=1
set OLLAMA_KEEP_ALIVE=300s
set OLLAMA_HOST=127.0.0.1:11434
set DO_NOT_TRACK=1
echo [2/3] Launching Backend in its own window...
start "SOAR Backend" cmd /k "call venv\Scripts\activate.bat && uvicorn main:app --port 8000"
timeout /t 8 > nul
echo [3/3] Launching Dashboard in its own window...
start "SOAR Dashboard" cmd /k "call venv\Scripts\activate.bat && streamlit run dashboard/app.py --theme.base=dark"
echo Both processes launched in separate windows. This window can be closed.