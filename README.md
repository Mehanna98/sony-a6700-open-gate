# Sony a6700 Open Gate (4K 3:2) + Cine EI + FL2/FL3 — 100% RAM-Only

Temporary, **zero-flash RAM-only** mod kit for the **Sony ILCE-6700 (a6700) on Firmware v2.00**.

Unlocks true **3:2 Open Gate (`3840 × 2560`, 10-bit 4:2:2)** with **full synced Gyroflow metadata (`18.76 ms` rolling shutter readout time)**, plus **FX30 Cine EI** and **FX2 FL2 / FL3 Creative Looks** — all stacked cleanly in RAM with **zero permanent changes to your camera**. Turning the camera off (or removing the battery) instantly returns everything to 100% factory stock.

![Sony a6700 3840x2560 Open Gate in Gyroflow](assets/gyroflow_proof.jpg)

---

## What's Included

| Feature | Status (a6700 FW v2.00) | Details |
|---|---|---|
| **Open Gate 4K 3:2** (`open_gate_4k.cmd`) | **Live-verified (PAL 25p)** | `3840 × 2560` (true 3:2, square pixels), 10-bit 4:2:2, 140 Mbps, 3:2 rear LCD preview with aligned AF/tracking frames, synced Sony Gyroflow metadata (`18.76 ms` readout). *(NTSC 24p included & calibrated; awaiting first NTSC tester.)* |
| **Cine EI** (`cine_ei.cmd`) | **Live-verified** | Unlocks Log Shooting → **Cine EI** (Base ISO 800 / 2500 + LUTs), stacks cleanly with Open Gate. |
| **FX2 FL2 & FL3 Looks** (`fl2_fl3.cmd`) | **Live-verified** | Loads authentic Sony FX2 **FL2** (onto Creative Look `IN`) and **FL3** (onto `SH`), stacks cleanly with Open Gate & Cine EI. |
| **All-in-One Combo** (`a6700_launcher.cmd` → `4`) | **Live-verified** | Guided 3-step run that stacks **Open Gate + Cine EI + FL2/FL3** in the same camera session. |
| **Pro Pack** (`a6700_launcher.cmd` → `7`) | *Built & offline-audited* | Optional AP-RAM unlocks: Power-Off Shutter Curtain, Flexible Exposure, Native FTP. |

---

## Safety Guarantees

- **100% RAM-only / zero flash writes:** Never touches `/dev/nflash*`, `/cp/cpapp-b.bin`, `/usr/lib/appFw.so`, or `/setting/BACKUP.BIN`. Power off / battery pull = 100% stock.
- **Strict Firmware v2.00 SHA-256 lock:** Every payload verifies the exact on-disk SHA-256 of `/libsencore.so`, `/libmpr.so`, `/libJiritsu.so`, `/usr/lib/appFw.so`, CP code pages, and every target byte before writing anything. If anything doesn't match stock ILCE-6700 FW v2.00, it aborts with `0` writes.
- **Automatic rollback:** If any write fails readback, every touched site is restored to stock automatically.
- **Same-session cleanup:** All temporary staging files in `/tmp/jiritsu/` are automatically deleted before the USB session closes.
- **Full source included:** Every `.so` payload in `payloads/` is compiled from freestanding C source in `src/` (`DT_NEEDED = 0`, `< 64 KiB`) and SHA-256 pinned in `payloads/manifest.json`.

---

## Windows Quick Start

### One-Time Setup
1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) (check **"Add Python to PATH"**).
2. Double-click **`windows\setup.cmd`** — creates a local `.venv`, installs `pyusb` + `pycryptodomex`, and runs an offline payload verification check.
3. Install the **`libusb-win32`** USB driver with **[Zadig](https://zadig.akeo.ie/)**:
   - On the camera: **Menu → Setup → USB → USB Connection Mode → Mass Storage (MSC)**.
   - Connect the camera to your PC via USB (it will appear as Mass Storage / `ILCE-6700`).
   - Open **Zadig → Options → List All Devices**, select your Sony camera (`VID 054C / PID 0E76`), and replace the driver with **`libusb-win32`**.
   - *(On the very first run, the camera switches to Sony Service Mode `PID 0336`; if Windows doesn't assign `libusb-win32` to `0336` automatically, run Zadig once more on `0336` too.)*

### Running Open Gate (Every Time You Want to Shoot)
1. Set your camera's Movie format to **XAVC S 4K 25p** (PAL) *(or 24p NTSC)*.
2. **Power the camera ON while the mode dial is on Photo / Stills** *(important! Open Gate must patch the raw buffer table before Movie mode initializes its memory pools)*.
3. Plug in USB → select **Mass Storage (MSC)**.
4. Double-click **`windows\open_gate_4k.cmd`** *(or **`windows\a6700_launcher.cmd`** for the full menu / All-in-One Combo)*.
5. Wait ~5 seconds for **`RESULT=APPLY_OK`**, unplug USB, and switch the dial to **Movie** — you're live in **3:2 Open Gate (`3840 × 2560`)**!

---

## Known Notes & Limitations

- **"Unable to display" during in-camera playback is completely normal:** Sony's built-in camera player only decodes 16:9 clips. Your `.MP4` files on the SD card (`PRIVATE\M4ROOT\CLIP\`) play cleanly in **Gyroflow, VLC, DaVinci Resolve, Premiere Pro**, etc.
- **Stay on XAVC S 4K 25p (or 24p) while Open Gate is active:** Avoid switching to **4K 50p / 60p** while Open Gate is loaded — 50p/60p shares part of the same sensor table and isn't wired up yet (switching to it will simply trigger a safe restart back to stock).
- **Returning to normal 16:9 stock requires a battery pull (~10 seconds):** Flipping the power switch OFF/ON only resets the sensor chip (Open Gate's sensor half + FL2/FL3) while Linux sleeps in RAM (keeping Cine EI and the `2560` encoder half loaded). If you want to go back to normal 16:9 shooting cleanly, **pull the battery for ~10 seconds** so both chips reset together. *(Conversely, if you flipped the power switch OFF/ON and want Open Gate back, just boot on Photo/Stills and re-run `open_gate_4k.cmd` — Cine EI stays active!)*
- **Keeping Open Gate active between shots:** Leave the power switch ON, set **Power Save Start Time → Off**, and use a **USB-C PD power bank** or dummy battery for long sessions.
- **NLE compatibility tip:** If an editor displays 3:2 clips vertically squeezed, remuxing with `ffmpeg -i input.mp4 -map 0:v:0 -map 0:a? -c copy -movflags +faststart fixed.mp4` fixes the container flags *(note: stripping the `rtmd` track removes Gyroflow data, so run Gyroflow first on the original `.MP4`!)*.
- **Firmware v2.00 only:** Do not attempt to bypass the firmware check on other firmware versions.

---

## Technical Notes (How a6700 Open Gate v6 Works)

- **Exact 3:2 sensor readout (`5952 × 3968`):** Uses the IMX684's factory V-ROI mode (`r2 = 0x05`, `S5 = 2`, `S6 = 2`, `top_ob = 26`) with `H_act = 3968`, `S2 = 70` (active rows `76..4044`, cleanly clear of the 28-row top border), `vcn = 1990` (`0x07C6 < 0x0800`), `S10 = 80` (`pd_st = 2`, `pd_cnt = 40`, `S9 = 47`, `S8 = 121`), and `CSDrvParam` vertical sampling ratio `27/32` (`3968 × 27 / 32 = 3348.0` exact stock height → `3840 × 2560` square pixels).
- **Fits Sony's PAL 50.000 Hz `XVS` sync budget:** On PAL `0x0880` (`25p`), Sony clocks the sensor at `50.000 Hz` (`20.000 ms`, `v_tot = 4,230` total SLVS-EC lines). Earlier `4,112`-row builds overran `4,230` (`4,284` total lines), preventing `CamCoreL0` End-Of-Frame (`FW: Lost CamCoreL0 out`). At `3,968` rows, total SLVS-EC lines drop to **`4,136` (`19.56 ms < 20.00 ms`, `+94` lines V-blank margin)** and `S3 = 2,014 < VMAX 2,115`.
- **Preserves all 7 of 7 `key 0x57f` RAW DMM buffers:** `H_stg = 3,976` → `3,976 × 6,016 = 23,919,616 B` (`0x016CFC00`). Three buffers take `71,758,848 B <= 74,448,896 B` (stock `71.00 MiB` `0x6fa` parent pool, `+2.57 MiB` spare), satisfying the 6-buffer upfront allocation in `cpapp-b.bin` without parking any buffers.
- **Rebuilding from source:** Install Zig 0.13+ and run `python src/build.py`.

---

## Credits & Special Thanks

This project stands on the shoulders of awesome Sony camera research by the community:

- **[ArcaneLantern](https://github.com/ArcaneLantern)** — A7 IV & A7S III Open Gate architecture, ISP 3000-byte record mapping, DMM raw write buffer sizing, `lcdfill_v2`, and `ogfile2560` encoder methodology.
- **[FireHydrant / Himpq](https://github.com/himpq)** — Jiritsu USB service transport (`jiritsu.py`, MIT License) and BIONZ XR research.
- **[ma1co / Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)** — Sony MSC → Service Mode authentication (`sony-pmca-re`, MIT License).
- **Powerful6700 / A7C II & a6700 community researchers** — FX30 Cine EI, FX2 FL2/FL3 Creative Look tables, and Pro Pack feature research.
- **[Erlla/sony-a7m4-custom-firmware](https://github.com/Erlla/sony-a7m4-custom-firmware)**, **[DavidBuchanan314/fwtool.py](https://github.com/DavidBuchanan314/fwtool.py)**, and **[leogenot/sony-a7iv-feature-research](https://github.com/leogenot/sony-a7iv-feature-research)** — foundational BIONZ XR USB service & firmware analysis.

---

## License

Licensed under **GNU General Public License v3.0** (see [LICENSE](LICENSE)). Vendored third-party libraries retain their original MIT licenses in `runner/third_party/`.
