@echo off
rem 1-Plug All-in-One Combo: Open Gate v6.1 + Cine EI v2.2 + FX2 FL2/FL3 in ONE USB session
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --combo
echo.
pause
