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
echo           Pulling embedding model (nomic-embed-text)...
ollama pull nomic-embed-text
echo.
echo           Pulling reasoning model (qwen2.5:7b-instruct-q4_K_M)...
echo           This is ~4.4 GB. May take a few minutes on first run.
ollama pull qwen2.5:7b-instruct-q4_K_M
echo           Both models ready.

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
echo [STEP 6/6] Launching SOAR Capsule services...
echo ---------------------------------------------------------------
echo           Starting FastAPI backend on port 8000...
start "SOAR Backend" cmd /k "call venv\Scripts\activate.bat && uvicorn main:app --port 8000"
echo           Waiting 8 seconds for backend to initialize...
timeout /t 8 > nul
echo           Starting Streamlit SOC Dashboard...
start "SOAR Dashboard" cmd /k "call venv\Scripts\activate.bat && streamlit run dashboard/app.py --theme.base=dark"

echo.
echo ============================================================
echo   SOAR CAPSULE IS NOW RUNNING
echo.
echo   Backend API:    http://127.0.0.1:8000
echo   SOC Dashboard:  http://localhost:8501
echo.
echo   This window can be closed safely.
echo ============================================================
pause
