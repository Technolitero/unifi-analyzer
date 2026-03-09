@echo off
setlocal EnableDelayedExpansion
title UniFi Analyzer — Uninstaller

set "SERVICE_NAME=UnifiAnalyzer"
set "INSTALL_DIR=C:\Program Files\UnifiAnalyzer"

echo.
echo  =============================================
echo   UniFi Analyzer ^| Uninstaller
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
echo  This will stop and remove the UniFi Analyzer service
echo  and delete "%INSTALL_DIR%".
echo.
set /p "CONFIRM=  Type YES to continue: "
if /i not "!CONFIRM!" == "YES" (
    echo  Cancelled.
    pause & exit /b 0
)

:: ─────────────────────────────────────────────────────────────
:: Stop and remove the service
:: ─────────────────────────────────────────────────────────────
echo.
echo [1/2] Removing Windows service...

sc query "%SERVICE_NAME%" >nul 2>&1
if %errorlevel% == 0 (
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 4 /nobreak >nul
    if exist "%INSTALL_DIR%\nssm.exe" (
        "%INSTALL_DIR%\nssm.exe" remove "%SERVICE_NAME%" confirm >nul 2>&1
    ) else (
        sc delete "%SERVICE_NAME%" >nul 2>&1
    )
    echo     Service removed  OK
) else (
    echo     No service found  OK
)

:: ─────────────────────────────────────────────────────────────
:: Delete install directory
:: ─────────────────────────────────────────────────────────────
echo.
echo [2/2] Deleting "%INSTALL_DIR%"...

if exist "%INSTALL_DIR%" (
    rd /s /q "%INSTALL_DIR%"
    if !errorlevel! neq 0 (
        echo  [WARNING] Could not fully delete "%INSTALL_DIR%".
        echo  Some files may still be in use. Delete the folder manually after reboot.
    ) else (
        echo     Deleted  OK
    )
) else (
    echo     Directory not found  OK
)

echo.
echo  =============================================
echo   Uninstall complete.
echo  =============================================
echo.
pause
endlocal
