#!/usr/bin/env bash
set -euo pipefail

# One-time macOS setup for Sony ILCE-6700 (FW v2.00) v6.1 100% RAM-Only Launcher
# Works on Apple Silicon (M1/M2/M3/M4) and Intel Macs. Zero camera contact.

cd "$(dirname "$0")"

echo "============================================================"
echo "  Sony a6700 (FW v2.00) -- v6.1 macOS One-Time Setup"
echo "  Zero flash writes. Zero camera contact during setup."
echo "============================================================"
echo ""

# Ensure Homebrew libusb is installed
if command -v brew >/dev/null 2>&1; then
  if ! brew list libusb >/dev/null 2>&1; then
    echo "[1/3] Installing libusb via Homebrew..."
    brew install libusb
  else
    echo "[1/3] libusb already installed via Homebrew."
  fi
else
  echo "[WARN] Homebrew not found. Install Homebrew from https://brew.sh and run:"
  echo "       brew install libusb"
  echo ""
fi

# Pick python3
PY_BIN=""
for cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 "$(command -v python3 || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then
    PY_BIN="$cand"
    break
  fi
done

if [ -z "$PY_BIN" ]; then
  echo "[ERROR] python3 not found. Install it with: brew install python"
  read -r -p "Press Enter to exit..."
  exit 1
fi

echo "[2/3] Creating local Python environment (.venv_mac) with $PY_BIN..."
"$PY_BIN" -m venv .venv_mac
.venv_mac/bin/python -m pip install --upgrade pip >/dev/null
.venv_mac/bin/python -m pip install -r ../windows/requirements.txt

echo ""
echo "[3/3] Running offline payload & SHA-256 verification (0 USB calls)..."
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:/usr/local/lib:${DYLD_LIBRARY_PATH:-}"
.venv_mac/bin/python -I -B ../runner/a6700_ram_runner.py --dry-run

echo ""
echo "============================================================"
echo "  macOS SETUP COMPLETE!"
echo "  Next: run ./a6700_launcher_mac.command"
echo "============================================================"
read -r -p "Press Enter to close..."
