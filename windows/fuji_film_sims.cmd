@echo off
rem 1-click 4 Hardware Fujifilm Film Sims (FL/VV2/IN/SH) for Sony ILCE-6700 (FW v2.00) -- 100% RAM-only
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing: double-click setup.cmd once first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --fuji
echo.
echo If APPLY_OK: FL=Classic Chrome, VV2=Classic Neg, IN=Nostalgic Neg, SH=Eterna!
pause
