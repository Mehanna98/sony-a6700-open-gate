@echo off
title Project Wildcard a6700 (FW v2.00) -- Windows RAM-Only Loader
rem 1-click Windows loader for Project Wildcard a6700 (100% Zero-Flash RAM-Only)
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo First-time launch detected -- running automatic offline setup...
  echo.
  call "%~dp0setup.cmd" --no-pause
  if errorlevel 1 (
    echo.
    echo [ERROR] First-time setup failed.
    pause
    exit /b 1
  )
  echo.
)

set "PY=%~dp0.venv\Scripts\python.exe"
set "RUNNER=%~dp0..\runner\a6700_ram_runner.py"

rem Optional CLI passthrough (e.g., Project_Wildcard_a6700.cmd --dry-run or --clean)
if not "%~1"=="" (
  "%PY%" -I -B "%RUNNER%" %*
  exit /b %ERRORLEVEL%
)

cls
echo ============================================================
echo   Project Wildcard a6700 (FW v2.00) -- Windows RAM-Only Loader
echo   100%% Zero-Flash. 10s battery pull = 100%% factory stock.
echo ============================================================
echo.
echo BEFORE PRESSING ENTER:
echo   1. Freshly turn camera ON (after power-off or 10s battery pull).
echo   2. Leave the mode dial on PHOTO / STILLS (not Movie).
echo   3. Connect USB cable in Mass Storage (MSC) mode.
echo.
echo   [Enter]  Load Project Wildcard a6700 (Wildcard + Creative Looks menus)
echo   [C]      Clean leftover camera temp files (/tmp/jiritsu)
echo   [R]      Restore Creative Looks to 100%% factory stock
echo   [D]      Offline safety ^& SHA-256 payload check (zero USB)
echo   [Q]      Quit
echo.
set "CHOICE="
set /p "CHOICE=Press Enter to load Project Wildcard (or type C / R / D / Q): "

if /i "%CHOICE%"=="Q" exit /b 0
if /i "%CHOICE%"=="C" goto DO_CLEAN
if /i "%CHOICE%"=="R" goto DO_RESTORE
if /i "%CHOICE%"=="D" goto DO_DRY
if "%CHOICE%"=="" goto DO_WILDCARD
if /i "%CHOICE%"=="Y" goto DO_WILDCARD
if /i "%CHOICE%"=="GO" goto DO_WILDCARD

echo Unknown option: %CHOICE%
pause
exit /b 1

:DO_WILDCARD
echo.
echo Loading Project Wildcard a6700 (Creative Looks Pack + Native Menus)...
echo.
"%PY%" -I -B "%RUNNER%" --wildcard
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo ============================================================
  echo   DONE! You can unplug USB now.
  echo.
  echo   Your native in-camera menus are live in RAM:
  echo     1. Setup -^> Operation Customize -^> Wildcard
  echo        ^(4K Open Gate 3:2 ^| SD Speed Bypass ^| Power-Off Shutter ^| Cine EI^)
  echo     2. Exposure/Color -^> Color/Tone -^> Creative Looks
  echo        ^(Stock ^| FX2 FL2/FL3 ^| Fujifilm 8-Sim: Provia, Astia,
  echo         Velvia, Classic Neg., Classic Chrome, Pro Neg. Hi, Eterna, Acros^)
  echo ============================================================
) else (
  echo ============================================================
  echo   Loader exited with error code %RC%.
  echo   Quick fixes:
  echo     - 'dmm_57f_already_divided': pull battery 10s, keep dial on PHOTO, retry.
  echo     - 'leftover files in /tmp/jiritsu': reopen and type [C] to clean.
  echo     - First run on Windows: install libusb-win32 with Zadig ^(see README.md^).
  echo ============================================================
)
echo.
pause
exit /b %RC%

:DO_CLEAN
echo.
"%PY%" -I -B "%RUNNER%" --clean
echo.
pause
exit /b %ERRORLEVEL%

:DO_RESTORE
echo.
"%PY%" -I -B "%RUNNER%" --restore-looks
echo.
pause
exit /b %ERRORLEVEL%

:DO_DRY
echo.
"%PY%" -I -B "%RUNNER%" --dry-run
echo.
pause
exit /b %ERRORLEVEL%
