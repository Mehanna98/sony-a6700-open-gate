#!/usr/bin/env bash
set -euo pipefail

# One-time macOS setup for Project Wildcard a6700 (FW v2.00) -- 100% Zero-Flash RAM-Only
# Works on Apple Silicon (M1/M2/M3/M4) and Intel Macs.
# Bundles libusb via libusb-package (no Homebrew needed). Zero camera contact during setup.

export PATH="/opt/homebrew/bin:/usr/local/bin:/Library/Frameworks/Python.framework/Versions/Current/bin:$PATH"
cd "$(dirname "$0")" || exit 1

NO_PAUSE=0
if [ "${1:-}" = "--no-pause" ]; then
  NO_PAUSE=1
fi

finish() {
  local rc="$1"
  if [ "$NO_PAUSE" -eq 0 ]; then
    echo ""
    read -r -p "Press Return to close..."
  fi
  exit "$rc"
}

echo "============================================================"
echo "  Project Wildcard a6700 (FW v2.00) -- macOS One-Time Setup"
echo "  Zero flash writes. Zero camera contact during setup."
echo "============================================================"
echo ""

# Find a real Python 3.9+ with venv support (avoids Apple's uninitialized /usr/bin/python3 stub)
PY_BIN=""
for cand in \
  /opt/homebrew/bin/python3 \
  /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
  /usr/local/bin/python3 \
  "$(command -v python3 || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then
    if "$cand" -c 'import sys, venv; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
      PY_BIN="$cand"
      break
    fi
  fi
done

if [ -z "$PY_BIN" ]; then
  echo "[ERROR] Python 3.9 or later not found."
  echo "        Install Python from https://www.python.org/downloads/macos/"
  echo "        OR install Xcode Command Line Tools: xcode-select --install"
  echo "        Then double-click Project_Wildcard_a6700.command again."
  finish 1
fi

echo "[1/3] Creating local Python environment (.venv_mac) with: $PY_BIN"
"$PY_BIN" -m venv .venv_mac || finish 1

echo "[2/3] Installing USB & crypto packages (pyusb, pycryptodomex, libusb-package)..."
.venv_mac/bin/python -m pip install --upgrade pip >/dev/null || true
if ! .venv_mac/bin/python -m pip install -r requirements.txt; then
  echo ""
  echo "[WARN] libusb-package wheel install failed on this Python version; trying core packages + Homebrew libusb..."
  .venv_mac/bin/python -m pip install -r ../windows/requirements.txt || finish 1
  if [ ! -f /opt/homebrew/lib/libusb-1.0.dylib ] && [ ! -f /usr/local/lib/libusb-1.0.dylib ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install libusb || finish 1
    else
      echo "[ERROR] No libusb library found. Install Python 3.12 from python.org or run: brew install libusb"
      finish 1
    fi
  fi
fi

echo ""
echo "[3/3] Running offline payload & SHA-256 verification (0 USB calls)..."
.venv_mac/bin/python -I -B ../runner/a6700_ram_runner.py --dry-run || finish 1

echo ""
echo "============================================================"
echo "  macOS SETUP COMPLETE! (No USB driver install needed.)"
echo "  Next: double-click Project_Wildcard_a6700.command"
echo "============================================================"
finish 0
