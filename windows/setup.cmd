@echo off
title Project Wildcard a6700 -- One-Time Windows Setup
rem One-time Windows setup for Project Wildcard a6700 (FW v2.00) -- 100% RAM-Only
cd /d "%~dp0"

set "NO_PAUSE=0"
if /i "%~1"=="--no-pause" set "NO_PAUSE=1"

echo ============================================================
echo   Project Wildcard a6700 (FW v2.00) -- Windows One-Time Setup
echo   Zero flash writes. Zero camera contact during setup.
echo ============================================================
echo.

where py >nul 2>&1
if %errorlevel%==0 (
  set "PYCMD=py -3"
) else (
  where python >nul 2>&1
  if %errorlevel%==0 (
    set "PYCMD=python"
  ) else (
    echo [ERROR] Python 3 not found. Please install Python 3.10+ from https://www.python.org/
    echo         Make sure "Add Python to PATH" is checked during install.
    if "%NO_PAUSE%"=="0" pause
    exit /b 1
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating Python virtual environment in windows\.venv ...
  %PYCMD% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    if "%NO_PAUSE%"=="0" pause
    exit /b 1
  )
)

echo [2/3] Installing USB ^& crypto packages (pyusb, pycryptodomex)...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Package install failed.
  if "%NO_PAUSE%"=="0" pause
  exit /b 1
)

echo.
echo [3/3] Running offline payload ^& SHA-256 verification (0 USB calls)...
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --dry-run
if errorlevel 1 (
  echo [ERROR] Offline verification failed!
  if "%NO_PAUSE%"=="0" pause
  exit /b 1
)

echo.
echo ============================================================
echo   WINDOWS SETUP COMPLETE!
echo   First time only: install libusb-win32 with Zadig for your
echo   a6700 (see README.md), then double-click:
echo     Project_Wildcard_a6700.cmd
echo ============================================================
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0
