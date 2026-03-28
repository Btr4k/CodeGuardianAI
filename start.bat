@echo off
REM ╔══════════════════════════════════════════════════════╗
REM ║           CodeGuardianAI — Quick Start               ║
REM ║  Double-click this file to launch the app.           ║
REM ╚══════════════════════════════════════════════════════╝

title CodeGuardianAI Launcher
color 0B

echo.
echo ╔══════════════════════════════════════╗
echo ║       CodeGuardianAI  Launcher        ║
echo ╚══════════════════════════════════════╝
echo.

REM ── 1. Python ────────────────────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found.
    echo.
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

python -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.9 or higher is required.
    echo Please download it from https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found.

REM ── 2. Virtual environment ───────────────────────────────────────────────
if not exist "venv\" (
    echo [..] Creating virtual environment...
    python -m venv venv
    echo [OK] Virtual environment created.
)

REM Activate
call venv\Scripts\activate.bat

REM ── 3. Dependencies ──────────────────────────────────────────────────────
python -c "import streamlit" >nul 2>&1
if %errorlevel% neq 0 (
    echo [..] Installing dependencies - this takes about 1 minute on first run...
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    echo [OK] Dependencies installed.
) else (
    echo [OK] Dependencies already installed.
)

REM ── 4. API keys (.env) ───────────────────────────────────────────────────
if not exist ".env" (
    echo.
    echo [!] .env file not found. Let's set it up.
    echo.
    echo     You need at least one AI API key to use CodeGuardianAI.
    echo     Get your OpenAI key at:   https://platform.openai.com/api-keys
    echo     Get your Deepseek key at: https://platform.deepseek.com
    echo.
    set /p OKEY="    Enter your OpenAI API key   (press Enter to skip): "
    set /p DKEY="    Enter your Deepseek API key (press Enter to skip): "

    (
        echo # -- API Keys --
        echo OPENAI_API_KEY=%OKEY%
        echo DEEPSEEK_API_KEY=%DKEY%
        echo.
        echo # -- Optional --
        echo # APP_PASSWORD=your_password_here
        echo OPENAI_MODEL=gpt-3.5-turbo
        echo DEEPSEEK_MODEL=deepseek-chat
        echo CACHE_DURATION=86400
    ) > .env

    echo [OK] .env file created.
) else (
    echo [OK] .env file found.
)

REM ── 5. Required directories ──────────────────────────────────────────────
if not exist "logs\"    mkdir logs
if not exist "cache\"   mkdir cache
if not exist "uploads\" mkdir uploads
if not exist "reports\" mkdir reports

REM ── 6. Launch ────────────────────────────────────────────────────────────
echo.
echo ════════════════════════════════════════
echo   App starting at: http://localhost:8501
echo   Close this window to stop the app.
echo ════════════════════════════════════════
echo.

streamlit run app.py --server.headless true --browser.gatherUsageStats false --server.port 8501
pause
