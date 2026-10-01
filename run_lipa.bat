@echo off
:: ============================================================
:: LIPA Launcher — One-Click Ingress Pre-flight Auditor
:: Supports: Windows (PowerShell GUI) and Linux/WSL (interactive shell)
:: ============================================================
title LIPA — Local Ingress Pre-flight Auditor
chcp 65001 >nul

echo.
echo   +----------------------------------------------------------+
echo   ^|   LIPA  --  Local Ingress Pre-flight Auditor             ^|
echo   ^|   Zero-Execution AST Safety ^& Compatibility Gate         ^|
echo   +----------------------------------------------------------+
echo.
echo   Where do you want to run LIPA?
echo.
echo   [1]  Windows     (PowerShell GUI with file picker dialogs)
echo   [2]  WSL Ubuntu  (Linux terminal with zenity/whiptail/readline)
echo   [3]  Exit
echo.

set /p CHOICE="  Your choice [1]: "
if "%CHOICE%"=="" set CHOICE=1

if "%CHOICE%"=="1" goto :run_windows
if "%CHOICE%"=="2" goto :run_wsl
if "%CHOICE%"=="3" goto :exit_clean
echo   Invalid choice. Running Windows mode.
goto :run_windows

:: ----------------------------------------------------------
:run_windows
:: ----------------------------------------------------------
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lipa_runner.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo   [ERROR] PowerShell runner exited with code %ERRORLEVEL%
    pause
)
goto :eof

:: ----------------------------------------------------------
:run_wsl
:: ----------------------------------------------------------
echo.
echo   Detecting WSL distributions...

:: Check for Ubuntu first, fall back to default WSL
wsl --list --quiet 2>nul | findstr /i "Ubuntu" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   Found Ubuntu WSL -- launching shell launcher...
    echo.
    wsl -d Ubuntu -- bash "%~dp0run_lipa.sh"
) else (
    echo   Ubuntu not found -- using default WSL distro...
    echo.
    wsl -- bash "%~dp0run_lipa.sh"
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo   [NOTE] WSL exited with code %ERRORLEVEL%
    echo   If this is a LIPA verdict code (1=BLOCKED, 2=WARN), it is expected.
    pause
)
goto :eof

:: ----------------------------------------------------------
:exit_clean
:: ----------------------------------------------------------
echo   Goodbye.
timeout /t 1 /nobreak >nul
goto :eof
