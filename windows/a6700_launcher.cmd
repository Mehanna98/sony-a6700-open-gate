@echo off
rem Interactive 1-click launcher for Sony ILCE-6700 (FW v2.00) -- 100% RAM-only, zero flash writes
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python environment missing. Please double-click setup.cmd once first!
  echo.
  pause
  exit /b 1
)

:MENU
cls
echo ============================================================
echo   Sony a6700 (FW v2.00) -- 100%% RAM-Only Launcher
echo   Zero flash writes. Power off / battery pull = 100%% stock.
echo ============================================================
echo.
echo   Before applying Open Gate:
echo     - Turn camera ON while dial is on PHOTO / STILLS
echo     - Movie format saved as XAVC S 4K 25p (PAL) or 24p (NTSC)
echo     - Plug in USB and select Mass Storage (MSC)
echo.
echo   [1] Open Gate 4K 3:2 (3840x2560, 10-bit 4:2:2 + Gyroflow)
echo   [2] Cine EI (Base ISO 800 / 2500 + LUTs)
echo   [3] FX2 FL2 (IN) ^& FL3 (SH) Creative Looks
echo   [4] All-in-One Combo (Open Gate + Cine EI + FL2/FL3)
echo   ----------------------------------------------------------
echo   [5] Read-Only Safety Check (Open Gate / CP-RAM probe)
echo   [6] Read-Only Safety Check (Cine EI / AP-RAM probe)
echo   [7] Pro Pack (Shutter Curtain + Flex Exp + FTP -- experimental)
echo   [8] Clean camera temp files (/tmp/jiritsu)
echo   [0] Exit
echo.
set /p "CHOICE=Pick a number (0-8): "

if "%CHOICE%"=="1" goto DO_OG
if "%CHOICE%"=="2" goto DO_CEI
if "%CHOICE%"=="3" goto DO_FL23
if "%CHOICE%"=="4" goto DO_COMBO
if "%CHOICE%"=="5" goto DO_OG_PROBE
if "%CHOICE%"=="6" goto DO_PROBE
if "%CHOICE%"=="7" goto DO_PRO
if "%CHOICE%"=="8" goto DO_CLEAN
if "%CHOICE%"=="0" exit /b 0
goto MENU

:DO_OG
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --open-gate
echo.
echo If APPLY_OK: unplug USB and switch dial to Movie (XAVC S 4K 25p / 24p)!
pause
goto MENU

:DO_CEI
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --cine-ei
echo.
pause
goto MENU

:DO_FL23
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --fl23
echo.
echo If APPLY_OK: Creative Look IN = FL2, SH = FL3!
pause
goto MENU

:DO_COMBO
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --combo
echo.
pause
goto MENU

:DO_OG_PROBE
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --og-probe
echo.
pause
goto MENU

:DO_PROBE
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --probe
echo.
pause
goto MENU

:DO_PRO
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --pro-pack
echo.
pause
goto MENU

:DO_CLEAN
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --clean
echo.
pause
goto MENU
