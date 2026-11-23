@echo off
rem 1-click FX2 FL2 (IN) & FL3 (SH) Creative Looks for Sony ILCE-6700 (FW v2.00) -- 100% RAM-only
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --fl23
echo.
echo If APPLY_OK: open Creative Look -> IN = FL2, SH = FL3!
pause
