@echo off
setlocal EnableDelayedExpansion
title UniFi Analyzer Launcher

:: ─────────────────────────────────────────────────────────────
:: Configuration
:: ─────────────────────────────────────────────────────────────
set "APP_PORT=8080"
set "APP_HOST=127.0.0.1"
set "VENV_DIR=%~dp0.venv"
set "REQ_FILE=%~dp0requirements.txt"
set "MAIN_FILE=%~dp0main.py"
set "MIN_PYTHON_MAJOR=3"
set "MIN_PYTHON_MINOR=8"

echo.
echo  =============================================
echo   UniFi Analyzer ^| Launcher
echo  =============================================
echo.

:: ─────────────────────────────────────────────────────────────
:: 1. Locate Python
:: ─────────────────────────────────────────────────────────────
echo [1/4] Checking Python...

set "PYTHON_CMD="

:: Try py launcher first (Windows Python Launcher)
where py >nul 2>&1
if !errorlevel! == 0 (
    for /f "tokens=*" %%v in ('py --version 2^>^&1') do set "PY_VER_RAW=%%v"
    goto :check_version
)

:: Fall back to python3 then python
where python3 >nul 2>&1
if !errorlevel! == 0 ( set "PYTHON_CMD=python3" & goto :check_version_cmd )

where python >nul 2>&1
if !errorlevel! == 0 ( set "PYTHON_CMD=python" & goto :check_version_cmd )

echo.
echo  [ERROR] Python was not found on this machine.
echo.
echo  Install Python 3.8+ from https://www.python.org/downloads/
echo  Make sure to tick "Add Python to PATH" during installation.
echo.
pause
exit /b 1

:check_version_cmd
for /f "tokens=*" %%v in ('!PYTHON_CMD! --version 2^>^&1') do set "PY_VER_RAW=%%v"

:check_version
:: PY_VER_RAW looks like "Python 3.11.4"
for /f "tokens=2 delims= " %%v in ("!PY_VER_RAW!") do set "PY_VER=%%v"
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set "PY_MAJOR=%%a"
    set "PY_MINOR=%%b"
)

if !PY_MAJOR! LSS %MIN_PYTHON_MAJOR% goto :python_too_old
if !PY_MAJOR! == %MIN_PYTHON_MAJOR% (
    if !PY_MINOR! LSS %MIN_PYTHON_MINOR% goto :python_too_old
)

echo     Found !PY_VER_RAW!  OK

:: Resolve final python command for venv creation
if defined PYTHON_CMD goto :setup_venv
set "PYTHON_CMD=py"
goto :setup_venv

:python_too_old
echo.
echo  [ERROR] Python !PY_VER! is too old. Version %MIN_PYTHON_MAJOR%.%MIN_PYTHON_MINOR%+ is required.
echo  Install a newer version from https://www.python.org/downloads/
echo.
pause
exit /b 1

:: ─────────────────────────────────────────────────────────────
:: 2. Create / reuse virtual environment
:: ─────────────────────────────────────────────────────────────
:setup_venv
echo.
echo [2/4] Checking virtual environment...

if exist "%VENV_DIR%\Scripts\python.exe" (
    echo     Virtual environment already exists  OK
) else (
    echo     Creating virtual environment at .venv ...
    !PYTHON_CMD! -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo.
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo     Created  OK
)

set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"
set "VENV_UVICORN=%VENV_DIR%\Scripts\uvicorn.exe"

:: ─────────────────────────────────────────────────────────────
:: 3. Install / update dependencies
:: ─────────────────────────────────────────────────────────────
echo.
echo [3/4] Installing dependencies from requirements.txt...
echo.

"%VENV_PYTHON%" -m pip install --upgrade pip --quiet
"%VENV_PYTHON%" -m pip install -r "%REQ_FILE%" --upgrade --quiet

if !errorlevel! neq 0 (
    echo.
    echo  [ERROR] Dependency installation failed.
    echo  Check the output above for details.
    echo.
    pause
    exit /b 1
)

echo.
echo     Dependencies installed  OK

:: ─────────────────────────────────────────────────────────────
:: 4. Launch application
:: ─────────────────────────────────────────────────────────────
echo.
echo [4/4] Starting UniFi Analyzer...
echo.
echo  Access the app at: http://%APP_HOST%:%APP_PORT%
echo  Press Ctrl+C to stop the server.
echo.

:: Open browser after a short delay (1 second)
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start http://%APP_HOST%:%APP_PORT%"

:: Run uvicorn from the venv
"%VENV_UVICORN%" main:app --host %APP_HOST% --port %APP_PORT%

if !errorlevel! neq 0 (
    echo.
    echo  [ERROR] Server exited unexpectedly. See above for details.
    echo.
    pause
)

endlocal
