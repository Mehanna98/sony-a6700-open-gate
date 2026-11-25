@echo off
rem 1-click Factory-Stock Creative Look Restore (clears cached looks without wiping camera settings)
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --restore-looks
echo.
pause
