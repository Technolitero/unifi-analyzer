@echo off
setlocal EnableDelayedExpansion
title UniFi Analyzer — Installer

set "SERVICE_NAME=UnifiAnalyzer"
set "SERVICE_DISPLAY=UniFi Analyzer"
set "INSTALL_DIR=C:\Program Files\UnifiAnalyzer"
set "SOURCE_DIR=%~dp0"
set "MIN_PYTHON_MAJOR=3"
set "MIN_PYTHON_MINOR=8"
set "NSSM_URL=https://nssm.cc/release/nssm-2.24.zip"
set "NSSM_EXE=%INSTALL_DIR%\nssm.exe"

echo.
echo  =============================================
echo   UniFi Analyzer ^| Installer
echo  =============================================
echo.

:: ─────────────────────────────────────────────────────────────
:: Require administrator privileges
:: ─────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs -Wait"
    exit /b
)

echo  Running as Administrator  OK
echo.

:: ─────────────────────────────────────────────────────────────
:: 1. Locate Python 3.8+
:: ─────────────────────────────────────────────────────────────
echo [1/6] Checking Python...

set "PYTHON_CMD="

where py >nul 2>&1
if !errorlevel! == 0 (
    for /f "tokens=*" %%v in ('py --version 2^>^&1') do set "PY_VER_RAW=%%v"
    set "PYTHON_CMD=py"
    goto :check_ver
)
where python3 >nul 2>&1
if !errorlevel! == 0 (
    for /f "tokens=*" %%v in ('python3 --version 2^>^&1') do set "PY_VER_RAW=%%v"
    set "PYTHON_CMD=python3"
    goto :check_ver
)
where python >nul 2>&1
if !errorlevel! == 0 (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do set "PY_VER_RAW=%%v"
    set "PYTHON_CMD=python"
    goto :check_ver
)

echo.
echo  [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/
echo  Make sure "Add Python to PATH" is checked during installation.
echo.
pause & exit /b 1

:check_ver
for /f "tokens=2 delims= " %%v in ("!PY_VER_RAW!") do set "PY_VER=%%v"
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set "PY_MAJOR=%%a"
    set "PY_MINOR=%%b"
)
if !PY_MAJOR! LSS %MIN_PYTHON_MAJOR% goto :py_old
if !PY_MAJOR! == %MIN_PYTHON_MAJOR% if !PY_MINOR! LSS %MIN_PYTHON_MINOR% goto :py_old
echo     Found !PY_VER_RAW!  OK
goto :stop_service

:py_old
echo.
echo  [ERROR] Python !PY_VER! is too old. Version 3.8+ required.
echo.
pause & exit /b 1

:: ─────────────────────────────────────────────────────────────
:: 2. Stop and remove existing service (upgrade path)
:: ─────────────────────────────────────────────────────────────
:stop_service
echo.
echo [2/6] Checking for existing installation...

sc query "%SERVICE_NAME%" >nul 2>&1
if %errorlevel% == 0 (
    echo     Found existing service — stopping...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 4 /nobreak >nul

    if exist "%NSSM_EXE%" (
        "%NSSM_EXE%" remove "%SERVICE_NAME%" confirm >nul 2>&1
    ) else (
        sc delete "%SERVICE_NAME%" >nul 2>&1
    )

    :: Wait until SCM fully releases the service entry (up to 30 s)
    echo     Waiting for service to be fully removed...
    set /a _wait=0
    :wait_delete_loop
    sc query "%SERVICE_NAME%" >nul 2>&1
    if !errorlevel! == 0 (
        set /a _wait+=1
        if !_wait! geq 30 (
            echo  [ERROR] Service is still marked for deletion after 30 s.
            echo  Close Services.msc if it is open, then re-run this installer.
            pause & exit /b 1
        )
        timeout /t 1 /nobreak >nul
        goto :wait_delete_loop
    )
    echo     Removed  OK
) else (
    echo     No existing service found  OK
)

:: ─────────────────────────────────────────────────────────────
:: 3. Copy application files
:: ─────────────────────────────────────────────────────────────
echo.
echo [3/6] Copying files to "%INSTALL_DIR%"...

if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if !errorlevel! neq 0 (
        echo  [ERROR] Could not create "%INSTALL_DIR%"
        pause & exit /b 1
    )
)

for %%f in (
    main.py
    config_analyzer.py
    config_export.py
    credentials.py
    pcap_handler.py
    unifi_client.py
    requirements.txt
) do (
    copy /Y "%SOURCE_DIR%%%f" "%INSTALL_DIR%\%%f" >nul
    if !errorlevel! neq 0 (
        echo  [ERROR] Failed to copy %%f
        pause & exit /b 1
    )
)

if not exist "%INSTALL_DIR%\static" mkdir "%INSTALL_DIR%\static"
xcopy /Y /E /Q "%SOURCE_DIR%static\*" "%INSTALL_DIR%\static\" >nul
if !errorlevel! neq 0 (
    echo  [ERROR] Failed to copy static assets.
    pause & exit /b 1
)

echo     Files copied  OK

:: ─────────────────────────────────────────────────────────────
:: 4. Create virtual environment and install dependencies
:: ─────────────────────────────────────────────────────────────
echo.
echo [4/6] Setting up Python virtual environment...

set "VENV_DIR=%INSTALL_DIR%\.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_UVICORN=%VENV_DIR%\Scripts\uvicorn.exe"

if exist "%VENV_PYTHON%" (
    echo     Virtual environment already exists  OK
) else (
    !PYTHON_CMD! -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause & exit /b 1
    )
    echo     Created  OK
)

echo.
echo [5/6] Installing dependencies (this may take a minute)...
echo.

"%VENV_PYTHON%" -m pip install --upgrade pip --quiet
if !errorlevel! neq 0 (
    echo  [ERROR] pip upgrade failed.
    pause & exit /b 1
)

"%VENV_PYTHON%" -m pip install -r "%INSTALL_DIR%\requirements.txt" --upgrade --quiet
if !errorlevel! neq 0 (
    echo  [ERROR] Dependency installation failed.
    pause & exit /b 1
)

echo     Dependencies installed  OK

:: ─────────────────────────────────────────────────────────────
:: 5. Download NSSM (service manager)
:: ─────────────────────────────────────────────────────────────
echo.
echo [6/6] Setting up Windows service...

if not exist "%NSSM_EXE%" (
    echo     Downloading NSSM service manager...
    set "NSSM_ZIP=%TEMP%\nssm.zip"
    set "NSSM_TMP=%TEMP%\nssm-extract"

    powershell -NoProfile -Command "Invoke-WebRequest -Uri '%NSSM_URL%' -OutFile '!NSSM_ZIP!' -UseBasicParsing -ErrorAction Stop"
    if !errorlevel! neq 0 (
        echo.
        echo  [ERROR] Failed to download NSSM. Check internet connection.
        echo  Alternatively, download nssm.exe manually from https://nssm.cc
        echo  and place it at: %NSSM_EXE%
        echo  Then re-run this installer.
        echo.
        pause & exit /b 1
    )

    powershell -NoProfile -Command "Expand-Archive -Path '!NSSM_ZIP!' -DestinationPath '!NSSM_TMP!' -Force"
    powershell -NoProfile -Command "Copy-Item '!NSSM_TMP!\nssm-2.24\win64\nssm.exe' -Destination '%NSSM_EXE%' -Force"
    if !errorlevel! neq 0 (
        echo  [ERROR] Failed to extract NSSM.
        pause & exit /b 1
    )
    echo     NSSM downloaded  OK
) else (
    echo     NSSM already present  OK
)

:: ─────────────────────────────────────────────────────────────
:: 6. Register and start the Windows service via NSSM
:: ─────────────────────────────────────────────────────────────
echo     Registering service...

"%NSSM_EXE%" install "%SERVICE_NAME%" "%VENV_UVICORN%"
if !errorlevel! neq 0 (
    echo  [ERROR] NSSM service registration failed.
    pause & exit /b 1
)

"%NSSM_EXE%" set "%SERVICE_NAME%" AppParameters "main:app --host 0.0.0.0 --port 8080"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppDirectory   "%INSTALL_DIR%"
"%NSSM_EXE%" set "%SERVICE_NAME%" DisplayName    "%SERVICE_DISPLAY%"
"%NSSM_EXE%" set "%SERVICE_NAME%" Description    "UniFi Network Analyzer — web interface on http://localhost:8080"
"%NSSM_EXE%" set "%SERVICE_NAME%" Start          SERVICE_AUTO_START
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStdout      "%INSTALL_DIR%\logs\service.log"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStderr      "%INSTALL_DIR%\logs\service-error.log"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRotateFiles 1
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRotateBytes 5242880

if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"

echo     Starting service...
"%NSSM_EXE%" start "%SERVICE_NAME%"
if !errorlevel! neq 0 (
    echo  [WARNING] Service registered but could not start right now.
    echo  Check logs at: %INSTALL_DIR%\logs\service-error.log
    echo  Or start manually: sc start %SERVICE_NAME%
) else (
    echo     Service started  OK
)

:: ─────────────────────────────────────────────────────────────
:: Done
:: ─────────────────────────────────────────────────────────────
echo.
echo  =============================================
echo   Installation complete!
echo.
echo   The UniFi Analyzer service starts
echo   automatically each time Windows boots.
echo.
echo   Access the app at:  http://localhost:8080
echo   Service logs at:    %INSTALL_DIR%\logs\
echo  =============================================
echo.
pause
endlocal
