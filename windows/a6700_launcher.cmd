@echo off
rem Interactive 1-click launcher for Sony ILCE-6700 (FW v2.00) -- v6.1 (100% RAM-only, zero flash writes)
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
echo   Sony a6700 (FW v2.00) -- v6.1 100%% RAM-Only Launcher
echo   Zero flash writes. Battery pull (10s) = 100%% stock.
echo ============================================================
echo.
echo   Before applying Open Gate:
echo     - Turn camera ON while dial is on PHOTO / STILLS
echo     - Movie format: XAVC HS / S / S-I 4K 25p (PAL) or 24p (NTSC)
echo     - Plug in USB and select Mass Storage (MSC)
echo.
echo   [1] Open Gate v6.1 (4K 24p/25p 3:2 HS/S/S-I; 50p stays stock)
echo   [2] Cine EI v2.2 (Base ISO 800 / 2500 + LUTs)
echo   [3] FX2 FL2 (IN) ^& FL3 (SH) Creative Looks
echo   [4] Fujifilm 4-Sim Pack (FL=Chrome, VV2=ClNeg, IN=NostNeg, SH=Eterna)
echo   [5] 1-Plug Combo: Open Gate + Cine EI + FX2 FL2/FL3
echo   [6] 1-Plug Combo: Open Gate + Cine EI + Fujifilm 4-Sim Pack
echo   ----------------------------------------------------------
echo   [7] Restore Creative Looks to 100%% Factory Stock
echo   [8] Read-Only Safety Check (Open Gate / CP-RAM probe)
echo   [9] Read-Only Safety Check (Cine EI / AP-RAM probe)
echo   [P] Pro Pack (Shutter Curtain + Flex Exp + FTP -- experimental)
echo   [C] Clean camera temp files (/tmp/jiritsu)
echo   [0] Exit
echo.
set /p "CHOICE=Pick an option: "

if /i "%CHOICE%"=="1" goto DO_OG
if /i "%CHOICE%"=="2" goto DO_CEI
if /i "%CHOICE%"=="3" goto DO_FL23
if /i "%CHOICE%"=="4" goto DO_FUJI
if /i "%CHOICE%"=="5" goto DO_COMBO
if /i "%CHOICE%"=="6" goto DO_COMBO_FUJI
if /i "%CHOICE%"=="7" goto DO_RESTORE
if /i "%CHOICE%"=="8" goto DO_OG_PROBE
if /i "%CHOICE%"=="9" goto DO_PROBE
if /i "%CHOICE%"=="P" goto DO_PRO
if /i "%CHOICE%"=="C" goto DO_CLEAN
if "%CHOICE%"=="0" exit /b 0
goto MENU

:DO_OG
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --open-gate
echo.
echo If APPLY_OK: unplug USB and switch dial to Movie (XAVC HS/S/S-I 4K 25p or 24p)!
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

:DO_FUJI
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --fuji
echo.
echo If APPLY_OK: FL=Classic Chrome, VV2=Classic Neg, IN=Nostalgic Neg, SH=Eterna!
pause
goto MENU

:DO_COMBO
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --combo
echo.
pause
goto MENU

:DO_COMBO_FUJI
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --combo-fuji
echo.
pause
goto MENU

:DO_RESTORE
echo.
".venv\Scripts\python.exe" -I -B "..\runner\a6700_ram_runner.py" --restore-looks
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
