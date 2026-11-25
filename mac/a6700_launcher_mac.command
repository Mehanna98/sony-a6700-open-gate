#!/usr/bin/env bash
set -u

# Interactive macOS launcher for Sony ILCE-6700 (FW v2.00) -- v6.1 (100% RAM-only, zero flash writes)
cd "$(dirname "$0")"

if [ ! -x ".venv_mac/bin/python" ]; then
  echo "[ERROR] macOS Python environment missing."
  echo "        Run ./setup_mac.command once first!"
  echo "        (If double-clicking fails, open Terminal in this folder and run:"
  echo "         chmod +x *.command && ./setup_mac.command)"
  echo ""
  read -r -p "Press Enter to exit..."
  exit 1
fi

export DYLD_LIBRARY_PATH="/opt/homebrew/lib:/usr/local/lib:${DYLD_LIBRARY_PATH:-}"
PY=".venv_mac/bin/python"
RUNNER="../runner/a6700_ram_runner.py"

run_cmd() {
  local flag="$1"
  echo ""
  echo "Note: macOS requires admin password (sudo) for direct USB access to the camera."
  echo "Tip : If Finder mounted the camera card, eject/unmount it if USB reports busy."
  echo ""
  sudo DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH" "$PY" -I -B "$RUNNER" "$flag"
}

while true; do
  clear
  echo "============================================================"
  echo "  Sony a6700 (FW v2.00) -- v6.1 macOS 100% RAM-Only Launcher"
  echo "  Zero flash writes. Battery pull (10s) = 100% stock."
  echo "============================================================"
  echo ""
  echo "  Before applying Open Gate:"
  echo "    - Turn camera ON while dial is on PHOTO / STILLS"
  echo "    - Movie format: XAVC HS / S / S-I 4K 25p (PAL) or 24p (NTSC)"
  echo "    - Plug in USB and select Mass Storage (MSC)"
  echo ""
  echo "  [1] Open Gate v6.1 (4K 24p/25p 3:2 HS/S/S-I; 50p stays stock)"
  echo "  [2] Cine EI v2.2 (Base ISO 800 / 2500 + LUTs)"
  echo "  [3] FX2 FL2 (IN) & FL3 (SH) Creative Looks"
  echo "  [4] Fujifilm 4-Sim Pack (FL=Chrome, VV2=ClNeg, IN=NostNeg, SH=Eterna)"
  echo "  [5] 1-Plug Combo: Open Gate + Cine EI + FX2 FL2/FL3"
  echo "  [6] 1-Plug Combo: Open Gate + Cine EI + Fujifilm 4-Sim Pack"
  echo "  ----------------------------------------------------------"
  echo "  [7] Restore Creative Looks to 100% Factory Stock"
  echo "  [8] Read-Only Safety Check (Open Gate / CP-RAM probe)"
  echo "  [9] Read-Only Safety Check (Cine EI / AP-RAM probe)"
  echo "  [p] Pro Pack (Shutter Curtain + Flex Exp + FTP -- experimental)"
  echo "  [c] Clean camera temp files (/tmp/jiritsu)"
  echo "  [d] Offline Payload Verify (--dry-run, no USB)"
  echo "  [0] Exit"
  echo ""
  read -r -p "Pick an option: " CHOICE

  case "$CHOICE" in
    1)
      run_cmd --open-gate
      echo ""
      echo "If APPLY_OK: unplug USB and switch dial to Movie (XAVC HS/S/S-I 4K 25p or 24p)!"
      read -r -p "Press Enter to return to menu..."
      ;;
    2)
      run_cmd --cine-ei
      read -r -p "Press Enter to return to menu..."
      ;;
    3)
      run_cmd --fl23
      echo ""
      echo "If APPLY_OK: Creative Look IN = FL2, SH = FL3!"
      read -r -p "Press Enter to return to menu..."
      ;;
    4)
      run_cmd --fuji
      echo ""
      echo "If APPLY_OK: FL=Classic Chrome, VV2=Classic Neg, IN=Nostalgic Neg, SH=Eterna!"
      read -r -p "Press Enter to return to menu..."
      ;;
    5)
      run_cmd --combo
      read -r -p "Press Enter to return to menu..."
      ;;
    6)
      run_cmd --combo-fuji
      read -r -p "Press Enter to return to menu..."
      ;;
    7)
      run_cmd --restore-looks
      read -r -p "Press Enter to return to menu..."
      ;;
    8)
      run_cmd --og-probe
      read -r -p "Press Enter to return to menu..."
      ;;
    9)
      run_cmd --probe
      read -r -p "Press Enter to return to menu..."
      ;;
    p|P)
      run_cmd --pro-pack
      read -r -p "Press Enter to return to menu..."
      ;;
    c|C)
      run_cmd --clean
      read -r -p "Press Enter to return to menu..."
      ;;
    d|D)
      echo ""
      "$PY" -I -B "$RUNNER" --dry-run
      read -r -p "Press Enter to return to menu..."
      ;;
    0)
      exit 0
      ;;
    *)
      ;;
  esac
done
