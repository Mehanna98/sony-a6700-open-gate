@echo off
rem 1-click Open Gate v6.1 (4K 24p/25p 3:2 HS/S/S-I) for Sony ILCE-6700 (FW v2.00) -- 100% RAM-only
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --open-gate
echo.
echo If APPLY_OK: unplug USB and switch the dial to Movie (XAVC HS / S / S-I 4K 25p or 24p)!
pause
