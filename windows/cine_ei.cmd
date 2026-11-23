@echo off
rem 1-click Cine EI (Base ISO 800 / 2500) for Sony ILCE-6700 (FW v2.00) -- 100% RAM-only
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --cine-ei
echo.
pause
