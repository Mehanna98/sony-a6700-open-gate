# Project Wildcard a6700

**100% Zero-Flash, RAM-Only Native In-Camera Menus for the Sony ILCE-6700 (a6700) on Firmware v2.00.**

One 10-second USB plug-in from **macOS** or **Windows** installs two native Sony menus directly into camera RAM — giving you instant on-camera toggles for **4K 3:2 Open Gate (`3840 × 2560`, 24p/25p/50p + 3:2 playback fix)**, **SD Card Speed Bypass**, **Power-Off Shutter Curtain**, **FX30 Cine EI / Cine EI Quick**, and a live **Creative Looks Pack Switcher** (**Stock**, **FX2 FL2/FL3**, and **8 Hardware Fujifilm Film Simulations** with full live native Sony menu names).

Nothing is ever written to camera flash. Pulling the battery for 10 seconds always returns your a6700 to **100% factory stock**.

![Sony a6700 3840x2560 Open Gate in Gyroflow](assets/gyroflow_proof.jpg)

---

## Native In-Camera Menus (Zero Reboot Needed)

After one quick USB run, unplug the cable and control everything straight from the camera's own menus:

### 1. `Setup → Operation Customize → Wildcard`
Toggle any feature **ON** or **OFF** anytime right on the camera:

| Toggle | What it does | Where to use it |
|---|---|---|
| **4K Open Gate (3:2)** | Switches between full-sensor **`3840 × 2560` (3:2, 10-bit 4:2:2)** across **XAVC HS 4K, XAVC S 4K, and XAVC S-I 4K All-Intra** (24p NTSC / 25p PAL / 50p PAL) with **in-camera 3:2 playback**, native 3:2 MP4 headers, and synced Gyroflow metadata (`18.76 ms` readout) — or back to stock `16:9` | Movie mode (4K formats show **`OG`** badge when ON; do not select 100p/120p while Open Gate is ON) |
| **SD Speed Bypass** | Bypasses Sony's SD speed-class lockout in RAM so V60/V30 cards can shoot high-bitrate 120p and All-Intra | Movie mode (works immediately) |
| **Power-Off Shutter** | Unlocks Sony's dust-protection shutter curtain on power-off | After setting ON here, enable **`Setup → Setup Option → Anti-dust Function → Shutter When Pwr OFF → On`** |
| **Cine EI / Quick** | Unlocks Sony FX30-style **Cine EI** & **Cine EI Quick** with dual Base ISO (`800 / 2500`) + LUTs | After setting ON here, go to **`Shooting → Image Quality/Rec → Log Shooting Setting`** |

### 2. `Exposure/Color → Color/Tone → Creative Looks`
Switch hardware ISP color packs live anytime (**zero reboot needed** — real-time in **Stills, 4K Video, and EVF**). Sony's native **`Creative Look`** menu, `Fn` screen, headers, and help descriptions automatically rename to match your active pack:

| Pack | Active Creative Look Slots & Live Camera UI Names | Untouched 100% Sony Stock |
|---|---|---|
| **Stock** | All 10 original Sony Creative Looks & native names | All 10 (`ST PT NT VV VV2 FL IN SH BW SE`) |
| **FX2 (FL2 / FL3)** | `IN` → **`FL2 (Film 2)`**, `SH` → **`FL3 (Film 3)`** | `ST PT NT VV VV2 FL BW SE` |
| **Fujifilm 8-Sim** | `ST` → **`Provia`**, `PT` → **`Astia`**, `VV` → **`Velvia`**, `VV2` → **`Classic Neg.`**, `FL` → **`Classic Chrome`**, `IN` → **`Pro Neg. Hi`**, `SH` → **`Eterna`**, `BW` → **`Acros`** | `NT` (Neutral), `SE` (Sepia) |

> **Tip:** Press the **`?` / Trash** Help button on any row inside `Wildcard` or `Creative Looks` for built-in notes right on the camera screen. The tiny graphical `[ST]`/`[FL]` stamp next to each Creative Look is a fixed bitmap icon, while all text labels, `Fn` titles, and descriptions dynamically show the active film simulation.

---

## macOS Quick Start (Apple Silicon & Intel — Zero Homebrew / No Drivers Needed)

Works out of the box on **M1 / M2 / M3 / M4** and **Intel Macs** (macOS bundles `libusb` automatically via `libusb-package` — no Homebrew and no USB driver installation required).

### Prerequisites
- **Python 3.9+** (install from [python.org](https://www.python.org/downloads/macos/) or run `xcode-select --install`).
- On the camera: **`Menu → Setup → USB → USB Connection Mode → Mass Storage (MSC)`**.

### Every Time You Want to Load Project Wildcard (~10 Seconds)
1. Turn your a6700 **ON** fresh (after a normal power-off or 10-second battery pull) while the mode dial is on **Photo / Stills** *(important! Leave the dial on Photo before plugging in so Open Gate's 3:2 video buffer expands cleanly before Movie mode initializes)*.
2. Plug the camera into your Mac via USB and select **Mass Storage (MSC)** *(close Photos / Image Capture if they pop up)*.
3. Open **`mac/Project_Wildcard_a6700.command`** (double-click it, or from Terminal):
   ```bash
   chmod +x mac/*.command
   ./mac/Project_Wildcard_a6700.command
   ```
   - On the very first launch, it automatically sets up `.venv_mac` and verifies all 17 payloads' SHA-256 hashes offline.
   - Press **Return**, enter your Mac login password when prompted *(needed once so macOS cleanly unmounts the SD card and hands USB control to Project Wildcard)*, and wait ~10 seconds for **`PROJECT WILDCARD a6700 IS LIVE IN CAMERA RAM!`**.
4. Unplug USB — both **`Wildcard`** and **`Creative Looks`** menus are live on your camera!

*(Optional: you can also run `./mac/setup_mac.command` ahead of time for offline setup with zero camera contact.)*

---

## Windows Quick Start

### One-Time Setup
1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) (check **"Add Python to PATH"**).
2. Install the **`libusb-win32`** USB driver using **[Zadig](https://zadig.akeo.ie/)**:
   - On the camera: **`Menu → Setup → USB → USB Connection Mode → Mass Storage (MSC)`**.
   - Connect the camera via USB, open **Zadig → Options → List All Devices**, select your Sony camera (`VID 054C / PID 0E76`), and replace the driver with **`libusb-win32`**.
   - *(On the very first run, the camera switches to Sony Service Mode `PID 0336`; if Windows doesn't assign `libusb-win32` to `0336` automatically, run Zadig once more on `0336` too.)*

### Every Time You Want to Load Project Wildcard (~10 Seconds)
1. Freshly turn your a6700 **ON** with the mode dial on **Photo / Stills**.
2. Connect USB in **Mass Storage (MSC)** mode.
3. Double-click **`windows\Project_Wildcard_a6700.cmd`** and press **Enter** *(automatically runs first-time Python setup & offline SHA-256 checks if needed)*.
4. Wait ~10 seconds for **`DONE! You can unplug USB now.`**, unplug USB, and enjoy both native menus!

---

## Returning to 100% Factory Stock

- **Instant in-camera toggle:** Switch any toggle in **`Wildcard`** to **OFF** or set **`Creative Looks`** to **`Stock`** anytime.
- **Full cold reset back to 100% factory stock:**
  1. If you enabled **Cine EI**, switch **`Log Shooting → Off`** first (Sony saves the active Log Shooting setting across reboots).
  2. If you used **FX2** or **Fujifilm 8-Sim** looks, select **`Stock`** inside **`Creative Looks`** (or run the `[r]` Restore Stock Looks option in the launcher) and **power the camera OFF normally once** so Sony clears its cached Creative Look tables cleanly.
  3. **Pull the battery for 10 seconds** → both AP Linux RAM and CP sensor RAM reset cleanly to **100% factory stock**.

---

## Safety Guarantees

- **100% Zero-Flash RAM-only:** Never touches `/dev/nflash*`, `/cp/cpapp-b.bin`, `/usr/lib/appFw.so`, or `/setting/BACKUP.BIN`. Zero CP executable code patches.
- **Strict Firmware v2.00 SHA-256 verification:** Every payload verifies the exact on-disk SHA-256 of `/libsencore.so`, `/libmpr.so`, `/libJiritsu.so`, `/usr/lib/appFw.so`, CP code pages, and every target byte before modifying RAM. If anything doesn't match stock ILCE-6700 FW v2.00, it aborts cleanly with `0` writes.
- **Safe macOS SD card unmount:** Before detaching Apple's USB mass-storage driver, the runner walks macOS's full I/O Registry (`ioreg`, including behind USB-C hubs/docks) and runs `diskutil unmountDisk` cleanly (aborting safely if Finder/Photos is using the card).
- **Same-session cleanup & automatic rollback:** Every staging file in `/tmp/jiritsu/` is verified via full SHA-256 readback before triggering and deleted in the exact same USB session.
- **Full source included & pinned:** All 17 freestanding AArch64 `.so` modules in `payloads/` compile cleanly (`-Wall -Wextra -Werror`, `DT_NEEDED = 0`, `0 R_AARCH64_GLOB_DAT`, `< 64 KiB`) from C source in `src/` via Zig 0.13+ (`python3 src/build.py`) and are SHA-256 pinned in `payloads/manifest.json`.

---

## Troubleshooting

- **`dmm_57f_already_divided`:** The camera was switched to Movie mode before plugging in USB. Unplug USB → turn OFF → pull battery for **10 seconds** → keep dial on **Photo / Stills** → turn ON → plug USB MSC → re-run.
- **`leftover files in /tmp/jiritsu/`:** Re-open `Project_Wildcard_a6700` and type **`c`** (or run `--clean`), then unplug/replug USB MSC and load again.
- **`Could not unmount` (macOS):** Close Finder windows, Photos, or Image Capture showing the camera's SD card and re-run.
- **4K 100p / 120p while Open Gate is ON:** The IMX684 sensor's 3:2 full-height readout supports **24p / 25p / 50p** — switch **4K Open Gate (3:2)** to **OFF** in the `Wildcard` menu before shooting 100p/120p slow motion.
- **Firmware v2.00 only:** Do not attempt to bypass the firmware check on other firmware versions.

---

## Credits & Special Thanks

Project Wildcard a6700 builds on incredible open Sony camera research by the community:

- **[ArcaneLantern](https://github.com/ArcaneLantern)** — A7 IV & A7S III Open Gate architecture, ISP 3000-byte record mapping, DMM raw write buffer sizing, `lcdfill_v2`, `ogfile2560`, and macOS `ioreg`/`libusb-package` USB takeover methodology.
- **[FireHydrant / Himpq](https://github.com/himpq)** — Jiritsu USB service transport (`jiritsu.py`, MIT License) and BIONZ XR research.
- **[ma1co / Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)** — Sony MSC → Service Mode authentication (`sony-pmca-re`, MIT License).
- **Powerful6700 / A7C II & a6700 community researchers** — FX30 Cine EI, FX2 FL2/FL3 Creative Look tables, and feature flag research.
- **[Erlla/sony-a7m4-custom-firmware](https://github.com/Erlla/sony-a7m4-custom-firmware)**, **[DavidBuchanan314/fwtool.py](https://github.com/DavidBuchanan314/fwtool.py)**, and **[leogenot/sony-a7iv-feature-research](https://github.com/leogenot/sony-a7iv-feature-research)** — foundational BIONZ XR USB service & firmware analysis.

---

## License

Licensed under **GNU General Public License v3.0** (see [LICENSE](LICENSE)). Vendored third-party libraries retain their original MIT licenses in `runner/third_party/`.
