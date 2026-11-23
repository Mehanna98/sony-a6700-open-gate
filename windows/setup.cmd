@echo off
rem One-time Windows setup for Sony a6700 Open Gate (FW v2.00)
cd /d "%~dp0"

echo ============================================================
echo   Sony a6700 Open Gate -- One-Time Windows Setup
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
    echo [ERROR] Python 3 not found. Please install Python 3 from https://www.python.org/
    echo         Make sure "Add Python to PATH" is checked during install.
    pause
    exit /b 1
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment in windows\.venv ...
  %PYCMD% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
  )
)

echo Installing USB & crypto packages (pyusb, pycryptodomex)...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Package install failed.
  pause
  exit /b 1
)

echo.
echo Running offline payload safety check (zero USB contact)...
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --dry-run
if errorlevel 1 (
  echo [ERROR] Offline verification failed!
  pause
  exit /b 1
)

echo.
echo ============================================================
echo   SETUP COMPLETE!
echo   Next (first time only): install libusb-win32 with Zadig
echo   for your a6700 (see README.md), then double-click
echo   a6700_launcher.cmd or open_gate_4k.cmd!
echo ============================================================
echo.
pause
