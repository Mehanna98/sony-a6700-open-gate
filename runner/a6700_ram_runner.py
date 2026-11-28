#!/usr/bin/env python3
"""a6700_ram_runner.py -- Portable zero-flash RAM-only runner for Project Wildcard a6700 (FW v2.00).

Supports macOS (Apple Silicon + Intel, zero Homebrew required) and Windows (libusb-win32).

Safety guarantees enforced on EVERY session:
  1. Verifies every payload's exact SHA-256 against payloads/manifest.json + ELF header checks
     (AArch64 ET_DYN, DT_INIT != 0, DT_NEEDED == 0, < 65,536 B, zero flash paths) before touching USB.
  2. On macOS, walks the full I/O Registry (including USB hubs/docks) and safely unmounts the
     camera's SD card via `diskutil unmountDisk` BEFORE detaching Apple's mass-storage driver.
  3. Refuses to proceed if leftover files exist in /tmp/jiritsu/ (unless --clean is explicitly run).
  4. Stages to stage.so and verifies full SHA-256 readback BEFORE triggering libJit.so.
  5. Saves timestamped camera reports to logs/ (gitignored) and deletes all temporary files
     in /tmp/jiritsu/ in the same session.
  6. 100% volatile RAM-only: a 10-second battery pull always returns the camera to 100% factory stock.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import plistlib
import struct
import subprocess
import sys
import time
from pathlib import Path

RUNNER_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUNNER_DIR.parent
PAYLOAD_DIR = REPO_ROOT / "payloads"
MANIFEST_PATH = PAYLOAD_DIR / "manifest.json"
LOGS_DIR = REPO_ROOT / "logs"

PMCA_DIR = RUNNER_DIR / "third_party" / "sony-pmca-re"
JIRITSU_DIR = RUNNER_DIR / "third_party" / "firehydrant"

SONY_VID = 0x054C
STAGE_NAME = "stage.so"
TRIGGER_NAME = "libJit.so"
RESULT_NAME = "rampatch.result"
MAX_BLOB = 65536


def load_manifest_hashes() -> dict[str, str]:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"Missing payload manifest: {MANIFEST_PATH}")
    doc = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {m["file"]: m["sha256"] for m in doc.get("modules", [])}


def verify_elf_payload(path: Path, expected_sha: str | None = None) -> dict:
    """Strictly validate a freestanding AArch64 Jiritsu .so payload offline."""
    data = path.read_bytes()
    if len(data) == 0 or len(data) >= MAX_BLOB:
        raise ValueError(f"{path.name}: size {len(data)} out of range (1..{MAX_BLOB - 1})")
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{path.name}: not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_class != 2 or ei_data != 1:
        raise ValueError(f"{path.name}: expected ELF64 LE (got class={ei_class}, data={ei_data})")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 3 or e_machine != 183:
        raise ValueError(f"{path.name}: expected ET_DYN(3)/EM_AARCH64(183), got type={e_type}/mach={e_machine}")

    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    pt_dynamic = None
    for i in range(e_phnum):
        p_type, _, p_off, _, _, p_fsz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize
        )
        if p_type == 2:
            pt_dynamic = (p_off, p_fsz)
    if pt_dynamic is None:
        raise ValueError(f"{path.name}: missing PT_DYNAMIC")

    dyn_off, dyn_sz = pt_dynamic
    dt_init = 0
    dt_needed = 0
    for off in range(dyn_off, dyn_off + dyn_sz, 16):
        tag, val = struct.unpack_from("<qQ", data, off)
        if tag == 0:
            break
        if tag == 12:
            dt_init = val
        elif tag == 1:
            dt_needed += 1
    if dt_init == 0:
        raise ValueError(f"{path.name}: missing DT_INIT")
    if dt_needed != 0:
        raise ValueError(f"{path.name}: has {dt_needed} DT_NEEDED deps (must be 0)")

    for bad in (b"/dev/nflash", b"/cp/cpapp", b"/setting/BACKUP"):
        if bad in data:
            raise ValueError(f"{path.name}: forbidden flash path {bad!r} found inside payload!")

    sha = hashlib.sha256(data).hexdigest()
    if expected_sha is not None and sha != expected_sha:
        raise ValueError(f"{path.name}: SHA-256 mismatch! got={sha}, expected={expected_sha}")
    return {"file": str(path), "size": len(data), "sha256": sha, "dt_init": hex(dt_init), "dt_needed": dt_needed}


# ---------------------------------------------------------------------------
# macOS USB support: bundled libusb-package + safe I/O Registry disk unmount
# ---------------------------------------------------------------------------

def _setup_macos_libusb() -> str:
    """Bind pyusb's libusb1 backend on macOS without relying on DYLD_LIBRARY_PATH.

    macOS SIP strips DYLD_LIBRARY_PATH when sudo runs. Loading libusb-package's bundled
    wheel first (or probing Homebrew's absolute dylib path via find_library) caches the
    libusb1 backend inside pyusb before PMCA-RE calls usb.core.find().
    """
    try:
        import libusb_package  # type: ignore

        backend = libusb_package.get_libusb1_backend()
        if backend is not None:
            return "libusb-package"
    except ImportError:
        pass

    import usb.backend.libusb1 as libusb1

    for cand in (
        "/opt/homebrew/lib/libusb-1.0.dylib",
        "/usr/local/lib/libusb-1.0.dylib",
        "/opt/local/lib/libusb-1.0.dylib",
    ):
        if os.path.isfile(cand):
            backend = libusb1.get_backend(find_library=lambda _name, p=cand: p)
            if backend is not None:
                return cand

    backend = libusb1.get_backend()
    return "system-libusb" if backend is not None else "none"


def _walk_ioreg(node: dict):
    yield node
    for child in node.get("IORegistryEntryChildren", []):
        if isinstance(child, dict):
            yield from _walk_ioreg(child)


def ioreg_sony_devices(run_fn=None) -> list[dict]:
    """Read-only walk of the macOS I/O Registry for Sony USB devices (direct or behind hubs)."""
    runner = run_fn or subprocess.run
    try:
        res = runner(
            ["ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"],
            capture_output=True,
            timeout=30,
        )
        out = res.stdout or b""
        tops = plistlib.loads(out) if out.strip() else []
    except Exception as exc:
        return [{"error": str(exc)}]

    rows: list[dict] = []
    for top in tops:
        if not isinstance(top, dict):
            continue
        for dev in _walk_ioreg(top):
            if dev.get("IOObjectClass") != "IOUSBHostDevice" or dev.get("idVendor") != SONY_VID:
                continue
            ifaces = [
                n for n in dev.get("IORegistryEntryChildren", [])
                if isinstance(n, dict) and n.get("IOObjectClass") == "IOUSBHostInterface"
            ]
            drivers = [
                d.get("IOObjectClass")
                for iface in ifaces
                for d in iface.get("IORegistryEntryChildren", [])
                if isinstance(d, dict) and d.get("IOObjectClass")
            ]
            disks = sorted({
                n["BSD Name"]
                for n in _walk_ioreg(dev)
                if n.get("IOObjectClass") == "IOMedia" and n.get("Whole") and n.get("BSD Name")
            })
            rows.append({
                "vid": SONY_VID,
                "pid": int(dev.get("idProduct", 0)),
                "location_id": int(dev.get("locationID", 0)),
                "name": dev.get("USB Product Name") or "Sony USB Device",
                "classes": [i.get("bInterfaceClass") for i in ifaces],
                "drivers": list(dict.fromkeys(drivers)),
                "disks": disks,
            })
    return rows


def prepare_macos_usb(
    svc_pid: int = 0x0336,
    euid_fn=None,
    run_fn=None,
    sleep_fn=None,
) -> list[str]:
    """Safely unmount Sony camera SD card(s) on macOS before libusb detaches Apple's MSC driver.

    Unmount only (`diskutil unmountDisk`): never writes to the card and never ejects the USB device.
    Returns the list of unmounted BSD disk names (empty if camera is already in Service Mode
    or has no card mounted).
    """
    get_euid = euid_fn or getattr(os, "geteuid", lambda: 0)
    runner = run_fn or subprocess.run
    sleeper = sleep_fn or time.sleep

    rows = ioreg_sony_devices(run_fn=runner)
    if not rows or any("error" in r for r in rows):
        err = rows[0]["error"] if rows else "no Sony USB device listed"
        raise RuntimeError(
            f"[macOS] Sony camera not found in macOS I/O Registry ({err}).\n"
            "        Make sure your a6700 is turned ON, plugged into your Mac via USB,\n"
            "        and set to USB Connection Mode -> Mass Storage (MSC)."
        )

    if all(r["pid"] == svc_pid for r in rows):
        print(f"[macOS] Sony Service Mode (054C:{svc_pid:04X}) already active -- no disk unmount needed.")
        return []

    if get_euid() != 0:
        raise RuntimeError(
            "[macOS] Admin rights (sudo) are required so macOS lets go of its USB mass-storage driver.\n"
            "        Run ./mac/Project_Wildcard_a6700.command (it prompts for your Mac password automatically)."
        )

    unmounted: list[str] = []
    for row in rows:
        if row["pid"] == svc_pid:
            continue
        disks_label = ", ".join(row["disks"]) if row["disks"] else "none"
        print(f"[macOS] Found {row['name']} (054C:{row['pid']:04X}), disks={disks_label}")
        for disk in row["disks"]:
            res = runner(
                ["diskutil", "unmountDisk", f"/dev/{disk}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            detail = ((res.stdout or "") + " " + (res.stderr or "")).strip()
            if res.returncode != 0:
                raise RuntimeError(
                    f"[macOS] Could not unmount the camera's SD card (/dev/{disk}: {detail}).\n"
                    "        Close Finder windows, Photos, or Image Capture showing the camera card and try again."
                )
            print(f"[macOS] Unmounted camera SD card (/dev/{disk}) cleanly.")
            unmounted.append(disk)

    if unmounted:
        sleeper(0.3)
    return unmounted


def _import_transport():
    if not PMCA_DIR.is_dir():
        raise SystemExit(f"Missing vendored sony-pmca-re at {PMCA_DIR}")
    if not (JIRITSU_DIR / "jiritsu.py").is_file():
        raise SystemExit(f"Missing FireHydrant jiritsu.py at {JIRITSU_DIR}")
    os.environ["PMCA_PATH"] = str(PMCA_DIR)
    for d in (str(PMCA_DIR), str(JIRITSU_DIR)):
        if d not in sys.path:
            sys.path.insert(0, d)
    import usb.core  # noqa: F401
    import Cryptodome  # noqa: F401

    if sys.platform == "darwin":
        backend_src = _setup_macos_libusb()
        if backend_src == "none":
            print(
                "[WARN] pyusb could not find libusb on macOS. Re-run ./mac/setup_mac.command "
                "(installs libusb-package automatically).",
                file=sys.stderr,
            )

    import jiritsu  # type: ignore
    return jiritsu


def _install_clean_senser_reader(ch) -> None:
    """Clean 1024-byte-aligned reader for service packets > 32 KiB (safe on macOS libusb1 & Windows libusb-win32)."""
    dev = getattr(ch, "channel", None)
    drv = getattr(dev, "driver", None)
    if dev is None or drv is None:
        return

    hdr_fmt = "<IHHBBBB"
    hdr_sz = struct.calcsize(hdr_fmt)
    part_max = 0x100000
    pkt_align = 1024

    def _clean_send_senser_packet(pFunc, data, oData=None):
        rem = bytes(data)
        while rem:
            header = struct.pack(hdr_fmt, len(rem), pFunc, dev._sequence, 0, 0, 0, 0)
            drv.write(header + rem[:part_max])
            rem = rem[part_max:]

        out = bytearray()
        total = None
        response = 0
        while True:
            raw = b""
            for _ in range(4):
                raw = drv.read(hdr_sz)
                if raw:
                    break
            if len(raw) != hdr_sz:
                raise RuntimeError(f"service answer header is {len(raw)} bytes, expected {hdr_sz}")
            size, _pfunc, seq, _ver, _mic, _off, response = struct.unpack(hdr_fmt, raw)
            if seq != dev._sequence:
                raise RuntimeError(f"wrong senser sequence {seq} (expected {dev._sequence})")
            if total is None:
                total = size
            part = min(total - len(out), part_max)
            got = 0
            empty = 0
            while got < part:
                want = min(part - got, 0x8000)
                ask = ((want + pkt_align - 1) // pkt_align) * pkt_align
                chunk = drv.read(ask)
                if not chunk:
                    empty += 1
                    if empty > 4:
                        raise RuntimeError(f"service answer stalled at {len(out) + got}/{total} bytes")
                    continue
                if len(chunk) > want:
                    raise RuntimeError(f"service answer overran part by {len(chunk) - want} bytes")
                empty = 0
                out += chunk
                got += len(chunk)
            if len(out) >= total:
                break
        dev._sequence += 1
        if oData is not None:
            oData.write(out)
            return response, None
        return response, bytes(out)

    dev.sendSenserPacket = _clean_send_senser_packet


def _dispose_driver(drv) -> None:
    """Release pyusb handle cleanly so macOS/Windows does not keep stale USB references."""
    dev = getattr(getattr(drv, "backend", None), "dev", None) or getattr(drv, "dev", None)
    if dev is None:
        return
    try:
        import usb.util

        usb.util.dispose_resources(dev)
    except Exception:
        pass


def _make_channel(jiritsu, allowed):
    """Create a macOS-safe, diagnostic-friendly Jiritsu Channel without modifying vendored libs."""
    if not hasattr(jiritsu, "_open_contexts"):
        return jiritsu.Channel(allowed=allowed)

    class _WildcardChannel(jiritsu.Channel):
        def __enter__(self):
            if sys.platform == "darwin":
                prepare_macos_usb(svc_pid=jiritsu.SVC_PID)

            self.ctxs = jiritsu._open_contexts()
            devs = jiritsu._list_sony(self.ctxs)
            jiritsu.log(f"visible Sony devices: {len(devs)}")
            for drv in devs:
                jiritsu.log(f"  id = {drv.getId()}")

            svc = [d for d in devs if d.getId()[1] == jiritsu.SVC_PID]
            if svc:
                jiritsu.log("service identity already present -- authenticating directly")
                self.auth = jiritsu._authenticate(svc[0])
                self.drv = svc[0]
            else:
                msc = None
                last_err = None
                for drv in devs:
                    if not isinstance(drv, (jiritsu.MscBbbDriver, jiritsu.GenericUsbDriver)):
                        continue
                    try:
                        info = jiritsu.MscDevice(drv).getDeviceInfo()
                        man = getattr(info, "manufacturer", "")
                        if isinstance(man, (bytes, bytearray)):
                            man = man.decode("utf-8", "ignore")
                        if "Sony" in str(man):
                            msc = drv
                            jiritsu.log(
                                f"MSC device: pid=0x{drv.getId()[1]:04X} model={getattr(info, 'model', '?')}"
                            )
                            break
                    except Exception as exc:
                        last_err = exc
                        jiritsu.log(f"  MSC probe on {drv.getId()} failed: {exc!r}")
                        continue

                if msc is None:
                    detail = f" (last USB error: {last_err})" if last_err else ""
                    if sys.platform == "darwin":
                        hint = (
                            "Make sure you ran via ./mac/Project_Wildcard_a6700.command (sudo), "
                            "closed Finder/Photos/Image Capture, and set USB Connection Mode -> Mass Storage (MSC)."
                        )
                    else:
                        hint = (
                            "Set the camera to Mass Storage (MSC) mode, replug USB, and make sure "
                            "libusb-win32 is installed via Zadig."
                        )
                    raise RuntimeError(f"no Sony MSC camera and no service identity{detail}. {hint}")

                jiritsu.log("asking the camera to raise the service identity ...")
                auth = jiritsu.SonySenserAuthDevice(msc)
                try:
                    auth.start()
                except Exception as exc:
                    jiritsu.log(f"start warning: {exc!r}")

                r1_note = None
                try:
                    auth.authenticate()
                    jiritsu.log("round 1 authentication passed")
                except Exception as exc:
                    # On some macOS / USB-C controllers, the camera starts re-enumerating to 0x0336
                    # right at the end of Round 1, closing the MSC pipe early. Poll for 0x0336!
                    r1_note = repr(exc)
                    jiritsu.log(f"round 1 exchange ended early ({r1_note}); polling for 0x{jiritsu.SVC_PID:04X} ...")

                try:
                    auth.stop()
                except Exception:
                    pass
                _dispose_driver(msc)

                deadline = time.time() + self.wait
                while time.time() < deadline:
                    time.sleep(0.75)
                    for drv in jiritsu._list_sony(self.ctxs, quiet=True):
                        if drv.getId()[1] != jiritsu.SVC_PID:
                            continue
                        try:
                            self.auth = jiritsu._authenticate(drv)
                            self.drv = drv
                            break
                        except Exception as exc:
                            jiritsu.log(f"  0x{jiritsu.SVC_PID:04X} authentication failed {exc!r}, retrying")
                    else:
                        continue
                    break
                else:
                    extra = f" (round 1 note: {r1_note})" if r1_note else ""
                    if sys.platform == "win32":
                        extra += " -- on Windows first run, install libusb-win32 for PID 0336 in Zadig and retry."
                    raise RuntimeError(f"service identity 0x{jiritsu.SVC_PID:04X} did not appear within {self.wait} s{extra}")
                jiritsu.log("round 2 authentication passed")

            jiritsu._set_timeout(self.drv)
            self.channel = jiritsu.SonySenserDevice(self.auth.driver)
            _install_clean_senser_reader(self)
            return self

        def __exit__(self, *args):
            try:
                super().__exit__(*args)
            finally:
                _dispose_driver(getattr(self, "drv", None))

    return _WildcardChannel(allowed=allowed)


def cmd_dry_run() -> None:
    print("=== PROJECT WILDCARD a6700 -- OFFLINE PAYLOAD CHECK (ZERO USB CONTACT) ===")
    jiritsu = _import_transport()
    if sys.platform == "darwin":
        print(f"[OK] macOS libusb backend: {_setup_macos_libusb()}")
    print(f"[OK] USB transport ready (MSC={jiritsu.MSC_PID:#06x}, SVC={jiritsu.SVC_PID:#06x})")
    pinned = load_manifest_hashes()
    for fname, exp_sha in pinned.items():
        p = PAYLOAD_DIR / fname
        if not p.is_file():
            raise SystemExit(f"[FAIL] Missing payload: {p}")
        info = verify_elf_payload(p, expected_sha=exp_sha)
        print(f"[OK] {fname:26s} {info['size']:6,d} B  DT_INIT={info['dt_init']}  sha256={info['sha256'][:16]}...")
    print(f"=== ALL {len(pinned)} PAYLOADS VERIFIED (0 USB CALLS MADE) ===")


def _print_recovery_hints(text: str) -> None:
    """Print plain-English recovery guidance for known safe-abort or completion states."""
    if "dmm_57f_already_divided" in text or "sizetbl_guards_uninitialized" in text:
        print(
            "[HINT] Camera video buffer memory was already partitioned (usually from switching\n"
            "       to Movie mode before plugging in, or from an earlier run).\n"
            "       Recovery: Turn camera OFF -> pull battery for 10 seconds -> reinsert ->\n"
            "       leave mode dial on Photo/Stills (not Movie) -> turn ON -> plug USB MSC -> retry."
        )
    elif "RESULT=ALREADY_APPLIED" in text or "RESULT=NOTHING_TO_DO" in text:
        print("[OK] Already active in camera RAM (0 bytes modified).")
    elif "RESULT=ALREADY_INSTALLED" in text:
        print("[OK] Native Wildcard & Creative Looks menus are already active in RAM (0 bytes modified).")
    elif "RESULT=RESTORE_STOCK_OK" in text:
        print(
            "[NEXT] Unplug USB, power the camera OFF normally once (saves clean stock Creative Look\n"
            "       tables to cache), then pull the battery for 10s -> 100% factory stock!"
        )


def _cleanup_channel_files(ch) -> None:
    for fn in (TRIGGER_NAME, STAGE_NAME, RESULT_NAME):
        try:
            if ch.read(fn, missing=True) is not None:
                ch.remove(fn)
                gone = ch.read(fn, missing=True) is None
                print(f"[CLEAN] /tmp/jiritsu/{fn} removed={gone}")
        except Exception as exc:
            print(f"[WARN] Cleanup failed for {fn}: {exc}", file=sys.stderr)


def _run_live_session(so_name: str, label: str, jiritsu_mod=None) -> str:
    pinned = load_manifest_hashes()
    so_path = PAYLOAD_DIR / so_name
    info = verify_elf_payload(so_path, expected_sha=pinned.get(so_name))
    print(f"[PREFLIGHT] Verified {so_path.name}: {info['size']:,} B, sha256={info['sha256'][:16]}...")

    blob = so_path.read_bytes()
    jiritsu = jiritsu_mod if jiritsu_mod is not None else _import_transport()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"{ts}_{label}.txt"

    allowed = (STAGE_NAME, TRIGGER_NAME, RESULT_NAME)
    text = ""
    with _make_channel(jiritsu, allowed) as ch:
        _install_clean_senser_reader(ch)
        stale = [fn for fn in allowed if ch.read(fn, missing=True) is not None]
        if stale:
            raise RuntimeError(
                f"Leftover files found in /tmp/jiritsu/: {stale}. Run with --clean first."
            )
        try:
            raw_res, _ = ch.run_module(
                blob=blob,
                stage_name=STAGE_NAME,
                out_name=RESULT_NAME,
                trigger_name=TRIGGER_NAME,
                force=False,
            )
            text = raw_res.decode("utf-8", "replace") if raw_res else "(empty result)"
            log_path.write_text(text, encoding="utf-8")
            print(f"[OK] Saved report to {log_path}")
            print("----- CAMERA REPORT BEGIN -----")
            print(text.rstrip())
            print("------ CAMERA REPORT END ------")
            _print_recovery_hints(text)
        finally:
            _cleanup_channel_files(ch)
    return text


def _run_multi_session(
    banner_title: str,
    steps: list[tuple[str, str, str]],
    done_lines: list[str],
    jiritsu_mod=None,
) -> list[tuple[str, str]]:
    """Run multiple verified payloads sequentially inside ONE single USB session."""
    pinned = load_manifest_hashes()
    prepared: list[tuple[str, str, bytes]] = []
    for title, so_name, label in steps:
        so_path = PAYLOAD_DIR / so_name
        info = verify_elf_payload(so_path, expected_sha=pinned.get(so_name))
        print(f"[PREFLIGHT] {title:40s} -> {so_name} ({info['size']:,} B, sha256={info['sha256'][:12]}...)")
        prepared.append((title, label, so_path.read_bytes()))

    print("\n============================================================")
    print(f"  {banner_title}")
    print(f"  Running {len(prepared)} modules inside ONE single USB session (~10-15s).")
    print("  Do NOT unplug USB until all modules complete!")
    print("============================================================\n")

    jiritsu = jiritsu_mod if jiritsu_mod is not None else _import_transport()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    allowed = (STAGE_NAME, TRIGGER_NAME, RESULT_NAME)
    results: list[tuple[str, str]] = []

    with _make_channel(jiritsu, allowed) as ch:
        _install_clean_senser_reader(ch)
        stale = [fn for fn in allowed if ch.read(fn, missing=True) is not None]
        if stale:
            raise RuntimeError(
                f"Leftover files found in /tmp/jiritsu/: {stale}. Run with --clean first."
            )
        try:
            total = len(prepared)
            for idx, (title, label, blob) in enumerate(prepared, start=1):
                print(f"\n=== [STEP {idx}/{total}] {title} ===")
                raw_res, _ = ch.run_module(
                    blob=blob,
                    stage_name=STAGE_NAME,
                    out_name=RESULT_NAME,
                    trigger_name=TRIGGER_NAME,
                    force=False,
                )
                text = raw_res.decode("utf-8", "replace") if raw_res else "(empty result)"
                log_path = LOGS_DIR / f"{ts}_{label}.txt"
                log_path.write_text(text, encoding="utf-8")
                print(f"[OK] Saved report to {log_path}")
                print("----- CAMERA REPORT BEGIN -----")
                print(text.rstrip())
                print("------ CAMERA REPORT END ------")
                _print_recovery_hints(text)
                results.append((title, text))
                _cleanup_channel_files(ch)

                ok = (
                    "RESULT=APPLY_OK" in text
                    or "RESULT=ALREADY_APPLIED" in text
                    or "RESULT=ALREADY_INSTALLED" in text
                    or "RESULT=NOTHING_TO_DO" in text
                )
                if not ok:
                    raise SystemExit(
                        f"\n[STOPPED] Step {idx}/{total} ({title}) did not return APPLY_OK / ALREADY_APPLIED. "
                        f"See {log_path}"
                    )
        finally:
            _cleanup_channel_files(ch)

    print("\n============================================================")
    for line in done_lines:
        print(f"  {line}")
    print("============================================================")
    return results


def cmd_wildcard(jiritsu_mod=None) -> list[tuple[str, str]]:
    """Install Project Wildcard a6700 native menus (Wildcard + Creative Looks 8-Sim Fuji / FX2 / Stock)."""
    return _run_multi_session(
        banner_title="PROJECT WILDCARD a6700 (FW v2.00) -- NATIVE RAM MENUS",
        steps=[
            ("Creative Looks Pack (Stock / FX2 / Fuji 8-Sim)", "a6700_looks_pack_ram.so", "wildcard_1_looks_pack"),
            ("Native Wildcard + Creative Looks Menus",         "a6700_og_menu_ram.so",    "wildcard_2_menus"),
        ],
        done_lines=[
            "PROJECT WILDCARD a6700 IS LIVE IN CAMERA RAM!",
            "You can unplug USB now. Open your camera menus:",
            "  1. Setup -> Operation Customize -> Wildcard",
            "     (4K Open Gate 3:2 | SD Speed Bypass | Power-Off Shutter | Cine EI)",
            "  2. Exposure/Color -> Color/Tone -> Creative Looks",
            "     (Stock | FX2 FL2/FL3 | Fujifilm 8-Sim with live full names)",
        ],
        jiritsu_mod=jiritsu_mod,
    )


def cmd_clean(jiritsu_mod=None) -> None:
    jiritsu = jiritsu_mod if jiritsu_mod is not None else _import_transport()
    allowed = (STAGE_NAME, TRIGGER_NAME, RESULT_NAME)
    with _make_channel(jiritsu, allowed) as ch:
        _install_clean_senser_reader(ch)
        for fn in allowed:
            if ch.read(fn, missing=True) is not None:
                ch.remove(fn)
                print(f"[CLEAN] Removed /tmp/jiritsu/{fn}")
            else:
                print(f"[OK] /tmp/jiritsu/{fn} already clean")


def cmd_combo(use_fuji: bool = False, jiritsu_mod=None) -> list[tuple[str, str]]:
    """Legacy 1-Plug direct combo: Open Gate + Cine EI + FX2 FL2/FL3 (or Fujifilm 8-Sim) without native menus."""
    look_step = (
        ("Fujifilm 8-Sim Pack (Provia..Acros)", "a6700_fuji_ram.so", "combo_3_fuji")
        if use_fuji
        else ("FX2 FL2 (IN) & FL3 (SH)", "a6700_fl23_ram.so", "combo_3_fl23")
    )
    return _run_multi_session(
        banner_title="Sony a6700 (FW v2.00) -- DIRECT 1-PLUG COMBO",
        steps=[
            ("Open Gate (4K 24p/25p/50p 3:2)", "a6700_og_ram.so",      "combo_1_og_ram"),
            ("Cine EI v2.2 (Base ISO 800/2500)", "a6700_cine_ei_ram.so", "combo_2_cine_ei"),
            look_step,
        ],
        done_lines=[
            "ALL 3 MODULES ARE LIVE IN RAM (1 USB SESSION)!",
            "Unplug USB and switch to Movie (XAVC HS / S / S-I 4K).",
            (
                "Creative Looks: ST=Provia, PT=Astia, VV=Velvia, VV2=Classic Neg, FL=Classic Chrome, IN=Pro Neg Hi, SH=Eterna, BW=Acros."
                if use_fuji
                else "Creative Looks: IN=FX2 FL2, SH=FX2 FL3."
            ),
        ],
        jiritsu_mod=jiritsu_mod,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Project Wildcard a6700 -- Zero-flash RAM-only runner (FW v2.00)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--wildcard",      action="store_true", help="Install Project Wildcard native menus (Wildcard + Creative Looks 8-Sim Fuji / FX2 / Stock)")
    g.add_argument("--og-menu",       action="store_true", help="Alias for --wildcard")
    g.add_argument("--dry-run",       action="store_true", help="Verify all payloads & Python USB stack offline (no USB)")
    g.add_argument("--clean",         action="store_true", help="Remove any leftover temp files in /tmp/jiritsu/")
    g.add_argument("--restore-looks", action="store_true", help="Restore Creative Look CP tables & cache to 100%% factory stock")
    g.add_argument("--probe",         action="store_true", help="Read-only AP-RAM safety check (Cine EI / Pro Pack)")
    g.add_argument("--og-probe",      action="store_true", help="Read-only CP-RAM safety check (Open Gate / Creative Looks)")
    g.add_argument("--open-gate",     action="store_true", help="Apply RAM-only Open Gate (4K 3:2) directly without menu")
    g.add_argument("--og-off",        action="store_true", help="Revert Open Gate RAM sites back to stock 16:9")
    g.add_argument("--sd-bypass",     action="store_true", help="Apply RAM-only SD Card Speed-Limit Bypass directly")
    g.add_argument("--sd-bypass-off", action="store_true", help="Restore stock SD Card Speed-Limit check")
    g.add_argument("--cine-ei",       action="store_true", help="Apply RAM-only Cine EI v2.2 directly")
    g.add_argument("--fl23",          action="store_true", help="Apply RAM-only FX2 FL2 (IN) & FL3 (SH) directly")
    g.add_argument("--fuji",          action="store_true", help="Apply RAM-only Fujifilm 8-Sim Pack directly")
    g.add_argument("--combo",         action="store_true", help="Direct 1-Plug Combo: Open Gate + Cine EI + FX2 FL2/FL3")
    g.add_argument("--combo-fuji",    action="store_true", help="Direct 1-Plug Combo: Open Gate + Cine EI + Fujifilm 8-Sim Pack")
    g.add_argument("--pro-pack",      action="store_true", help="Apply RAM-only Pro Pack (Shutter Curtain + Flex Exp + FTP)")
    g.add_argument("--shutter",       action="store_true", help="Apply RAM-only Power-Off Shutter Curtain")
    g.add_argument("--exposure",      action="store_true", help="Apply RAM-only Flexible Exposure")
    g.add_argument("--ftp",           action="store_true", help="Apply RAM-only Native FTP Transfer")
    args = ap.parse_args()

    if args.dry_run:
        cmd_dry_run()
    elif args.clean:
        cmd_clean()
    elif args.wildcard or args.og_menu:
        cmd_wildcard()
    elif args.combo:
        cmd_combo(use_fuji=False)
    elif args.combo_fuji:
        cmd_combo(use_fuji=True)
    elif args.probe:
        _run_live_session("a6700_probe_ro.so", "probe_ro")
    elif args.og_probe:
        _run_live_session("a6700_og_probe_ro.so", "og_probe_ro")
    elif args.open_gate:
        _run_live_session("a6700_og_ram.so", "og_apply_ram")
    elif args.og_off:
        _run_live_session("a6700_og_off_ram.so", "og_off_ram")
    elif args.sd_bypass:
        _run_live_session("a6700_sd_bypass_ram.so", "sd_bypass_ram")
    elif args.sd_bypass_off:
        _run_live_session("a6700_sd_bypass_off_ram.so", "sd_bypass_off_ram")
    elif args.cine_ei:
        _run_live_session("a6700_cine_ei_ram.so", "cine_ei_ram")
    elif args.fl23:
        _run_live_session("a6700_fl23_ram.so", "fl23_ram")
    elif args.fuji:
        _run_live_session("a6700_fuji_ram.so", "fuji_ram")
    elif args.restore_looks:
        _run_live_session("a6700_cc_restore_stock.so", "restore_looks")
    elif args.pro_pack:
        _run_live_session("a6700_features_ram.so", "pro_pack_ram")
    elif args.shutter:
        _run_live_session("a6700_shutter_ram.so", "shutter_ram")
    elif args.exposure:
        _run_live_session("a6700_exposure_ram.so", "exposure_ram")
    elif args.ftp:
        _run_live_session("a6700_ftp_ram.so", "ftp_ram")


if __name__ == "__main__":
    main()
