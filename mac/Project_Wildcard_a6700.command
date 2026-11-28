#!/usr/bin/env bash
set -u

# Project Wildcard a6700 (FW v2.00) -- 1-Click macOS RAM-Only Loader (100% Zero-Flash)
# Works on Apple Silicon (M1/M2/M3/M4) and Intel Macs.
# Auto-runs one-time Python/libusb setup if .venv_mac is not created yet.

export PATH="/opt/homebrew/bin:/usr/local/bin:/Library/Frameworks/Python.framework/Versions/Current/bin:$PATH"
cd "$(dirname "$0")" || exit 1

SCRIPT_DIR="$PWD"
PY="$SCRIPT_DIR/.venv_mac/bin/python"
RUNNER="$SCRIPT_DIR/../runner/a6700_ram_runner.py"
LOGS_DIR="$SCRIPT_DIR/../logs"

pause_and_exit() {
  local rc="$1"
  echo ""
  read -r -p "Press Return to close..."
  exit "$rc"
}

# Auto-run one-time offline setup on first launch
if [ ! -x "$PY" ]; then
  echo "First-time launch detected -- running automatic offline setup (no Homebrew needed)..."
  echo ""
  bash "$SCRIPT_DIR/setup_mac.command" --no-pause
  rc=$?
  if [ "$rc" -ne 0 ] || [ ! -x "$PY" ]; then
    echo ""
    echo "[ERROR] First-time setup did not finish (exit code $rc)."
    pause_and_exit 1
  fi
  echo ""
fi

run_as_root() {
  echo ""
  echo "macOS will ask for your Mac login password (needed once so macOS lets go"
  echo "of its USB storage driver and hands the camera to Project Wildcard)."
  echo "(Characters won't show while typing -- just type your password and press Return.)"
  echo ""
  # Run inside one root shell and restore ownership of logs/ even on Ctrl+C.
  sudo /bin/bash -c '
    trap : INT
    logs_dir=$1
    shift
    "$@"
    rc=$?
    if [ -d "$logs_dir" ] && [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
      chown -R "$SUDO_UID:$SUDO_GID" "$logs_dir" 2>/dev/null || true
    fi
    exit $rc
  ' _ "$LOGS_DIR" "$PY" -I -B "$RUNNER" "$@"
}

# Optional direct CLI passthrough (e.g., ./Project_Wildcard_a6700.command --dry-run or --clean)
if [ "$#" -gt 0 ]; then
  case " $* " in
    *" --dry-run "*|*" -h "*|*" --help "*)
      "$PY" -I -B "$RUNNER" "$@"
      exit $?
      ;;
    *)
      run_as_root "$@"
      exit $?
      ;;
  esac
fi

clear 2>/dev/null || true
echo "============================================================"
echo "  Project Wildcard a6700 (FW v2.00) -- macOS RAM-Only Loader"
echo "  100% Zero-Flash. 10s battery pull = 100% factory stock."
echo "============================================================"
echo ""
echo "BEFORE PRESSING RETURN:"
echo "  1. Freshly turn camera ON (after power-off or 10s battery pull)."
echo "  2. Leave the mode dial on PHOTO / STILLS (not Movie)."
echo "  3. Connect USB cable in Mass Storage (MSC) mode."
echo "     (Close Photos / Image Capture if they open automatically.)"
echo ""
echo "  [Return]  Load Project Wildcard a6700 (Wildcard + Creative Looks menus)"
echo "  [c]       Clean leftover camera temp files (/tmp/jiritsu)"
echo "  [r]       Restore Creative Looks to 100% factory stock"
echo "  [d]       Offline safety & SHA-256 payload check (zero USB)"
echo "  [q]       Quit"
echo ""
read -r -p "Press Return to load Project Wildcard (or type c / r / d / q): " CHOICE

case "$CHOICE" in
  ""|y|Y|go|GO)
    echo ""
    echo "Loading Project Wildcard a6700 (Creative Looks Pack + Native Menus)..."
    run_as_root --wildcard
    rc=$?
    echo ""
    if [ "$rc" -eq 0 ]; then
      echo "============================================================"
      echo "  DONE! You can unplug USB now."
      echo ""
      echo "  Your native in-camera menus are live in RAM:"
      echo "    1. Setup -> Operation Customize -> Wildcard"
      echo "       (4K Open Gate 3:2 | SD Speed Bypass | Power-Off Shutter | Cine EI)"
      echo "    2. Exposure/Color -> Color/Tone -> Creative Looks"
      echo "       (Stock | FX2 FL2/FL3 | Fujifilm 8-Sim: Provia, Astia,"
      echo "        Velvia, Classic Neg., Classic Chrome, Pro Neg. Hi, Eterna, Acros)"
      echo "============================================================"
    else
      echo "============================================================"
      echo "  Loader exited with error code $rc."
      echo "  Quick fixes:"
      echo "    - 'dmm_57f_already_divided': pull battery 10s, keep dial on PHOTO, retry."
      echo "    - 'leftover files in /tmp/jiritsu': reopen and type [c] to clean."
      echo "    - 'Could not unmount': close Finder/Photos/Image Capture and retry."
      echo "============================================================"
    fi
    pause_and_exit "$rc"
    ;;
  c|C)
    run_as_root --clean
    pause_and_exit $?
    ;;
  r|R)
    run_as_root --restore-looks
    pause_and_exit $?
    ;;
  d|D)
    echo ""
    "$PY" -I -B "$RUNNER" --dry-run
    pause_and_exit $?
    ;;
  q|Q)
    exit 0
    ;;
  *)
    echo "Unknown option: $CHOICE"
    pause_and_exit 1
    ;;
esac
