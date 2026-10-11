@echo off
TITLE SOAR CAPSULE - AUTOMATED INSTALLER AND LAUNCHER
cd /d "%~dp0"
color 0A

echo ============================================================
echo   SOAR CAPSULE - ONE-CLICK SETUP AND LAUNCH
echo   Vikram Sarabhai Space Centre - Live Demo Build
echo ============================================================
echo.

REM ---- PRE-FLIGHT: Check Python is available ----
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Python is not installed or not in PATH.
    echo         Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

REM ---- PRE-FLIGHT: Check Ollama is available ----
ollama --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Ollama is not installed or not in PATH.
    echo         Download from https://ollama.com and install first.
    pause
    exit /b 1
)

echo.
echo [STEP 1/6] Creating isolated Python virtual environment...
echo ---------------------------------------------------------------
if not exist "venv\Scripts\activate.bat" (
    python -m venv venv
    echo           Virtual environment created.
) else (
    echo           Virtual environment already exists. Skipping.
)
call venv\Scripts\activate.bat

echo.
echo [STEP 2/6] Installing all required Python libraries...
echo ---------------------------------------------------------------
pip install -r requirements.txt --quiet
echo           All dependencies installed.

echo.
echo [STEP 3/6] Downloading AI Model weights via Ollama...
echo ---------------------------------------------------------------
echo           Pulling every model listed in config\hitl_config.yaml...
echo           (qwen3:8b is ~5.2 GB on first download)
for /f "usebackq delims=" %%M in (`python scripts\required_models.py`) do (
    echo           - %%M
    ollama pull %%M
)
echo           Models ready.

echo.
echo [STEP 4/6] Indexing threat playbooks into ChromaDB vector store...
echo ---------------------------------------------------------------
python -m rag.ingest_playbooks
echo           Playbook knowledge base built.

echo.
echo [STEP 5/6] Enforcing VRAM safety constraints...
echo ---------------------------------------------------------------
set OLLAMA_MAX_LOADED_MODELS=1
set OLLAMA_NUM_PARALLEL=1
set OLLAMA_KEEP_ALIVE=300s
set OLLAMA_HOST=127.0.0.1:11434
set DO_NOT_TRACK=1
echo           Single-model VRAM lock engaged.

echo.
echo [STEP 6/6] Building the web UI (first run only) and launching...
echo ---------------------------------------------------------------
if exist "frontend\dist\index.html" (
    echo           Web UI already built. Skipping.
) else (
    REM "if errorlevel" (not %%ERRORLEVEL%%) - variables inside a ( ) block expand at parse time
    call npm --version >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Node.js not found and frontend\dist is missing.
        echo        Install Node 18+ once, or copy a prebuilt frontend\dist from another machine.
        echo        The API still works at http://127.0.0.1:8000/docs
    ) else (
        pushd frontend
        call npm ci --no-audit --no-fund
        call npm run build
        popd
    )
)
echo           Starting the SOAR backend + UI on http://127.0.0.1:8000 ...
start "SOAR Capsule" cmd /k "call venv\Scripts\activate.bat && uvicorn main:app --host 127.0.0.1 --port 8000"
timeout /t 6 > nul
start "" http://127.0.0.1:8000

echo.
echo ============================================================
echo   SOAR CAPSULE IS NOW RUNNING
echo.
echo   SOC console:  http://127.0.0.1:8000
echo   API docs:     http://127.0.0.1:8000/docs
echo.
echo   This window can be closed safely.
echo ============================================================
pause
