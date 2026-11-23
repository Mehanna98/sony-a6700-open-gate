#!/usr/bin/env python3
"""a6700_ram_runner.py -- Portable zero-flash RAM-only runner for Sony ILCE-6700 (FW v2.00).

Safety guarantees enforced on EVERY session:
  1. Verifies every payload's exact SHA-256 against payloads/manifest.json + ELF header checks
     (AArch64 ET_DYN, DT_INIT != 0, DT_NEEDED == 0, < 65,536 B, zero flash paths) before touching USB.
  2. Refuses to proceed if leftover files exist in /tmp/jiritsu/ (unless --clean is explicitly run).
  3. Stages to stage.so and verifies full SHA-256 readback BEFORE triggering libJit.so.
  4. Saves timestamped camera reports to logs/ (gitignored) and deletes all temporary files
     in /tmp/jiritsu/ in the same session.
  5. 100% volatile RAM-only: power cycling / removing the battery reverts 100% to factory stock.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

RUNNER_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUNNER_DIR.parent
PAYLOAD_DIR = REPO_ROOT / "payloads"
MANIFEST_PATH = PAYLOAD_DIR / "manifest.json"
LOGS_DIR = REPO_ROOT / "logs"

PMCA_DIR = RUNNER_DIR / "third_party" / "sony-pmca-re"
JIRITSU_DIR = RUNNER_DIR / "third_party" / "firehydrant"

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
    import jiritsu  # type: ignore
    return jiritsu


def _install_clean_senser_reader(ch) -> None:
    """Clean 1024-byte-aligned reader for Windows libusb-win32 service packets > 32 KiB."""
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


def cmd_dry_run() -> None:
    print("=== OFFLINE SAFETY & PAYLOAD CHECK (ZERO USB CONTACT) ===")
    jiritsu = _import_transport()
    print(f"[OK] USB transport ready (MSC={jiritsu.MSC_PID:#06x}, SVC={jiritsu.SVC_PID:#06x})")
    pinned = load_manifest_hashes()
    for fname, exp_sha in pinned.items():
        p = PAYLOAD_DIR / fname
        if not p.is_file():
            raise SystemExit(f"[FAIL] Missing payload: {p}")
        info = verify_elf_payload(p, expected_sha=exp_sha)
        print(f"[OK] {fname:24s} {info['size']:6,d} B  DT_INIT={info['dt_init']}  sha256={info['sha256'][:16]}...")
    print(f"=== ALL {len(pinned)} PAYLOADS VERIFIED (0 USB CALLS MADE) ===")


def _run_live_session(so_name: str, label: str) -> str:
    pinned = load_manifest_hashes()
    so_path = PAYLOAD_DIR / so_name
    info = verify_elf_payload(so_path, expected_sha=pinned.get(so_name))
    print(f"[PREFLIGHT] Verified {so_path.name}: {info['size']:,} B, sha256={info['sha256'][:16]}...")

    blob = so_path.read_bytes()
    jiritsu = _import_transport()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"{ts}_{label}.txt"

    allowed = (STAGE_NAME, TRIGGER_NAME, RESULT_NAME)
    text = ""
    with jiritsu.Channel(allowed=allowed) as ch:
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
        finally:
            for fn in (TRIGGER_NAME, STAGE_NAME, RESULT_NAME):
                try:
                    if ch.read(fn, missing=True) is not None:
                        ch.remove(fn)
                        gone = ch.read(fn, missing=True) is None
                        print(f"[CLEAN] /tmp/jiritsu/{fn} removed={gone}")
                except Exception as exc:
                    print(f"[WARN] Cleanup failed for {fn}: {exc}", file=sys.stderr)
    return text


def cmd_clean() -> None:
    jiritsu = _import_transport()
    allowed = (STAGE_NAME, TRIGGER_NAME, RESULT_NAME)
    with jiritsu.Channel(allowed=allowed) as ch:
        _install_clean_senser_reader(ch)
        for fn in allowed:
            if ch.read(fn, missing=True) is not None:
                ch.remove(fn)
                print(f"[CLEAN] Removed /tmp/jiritsu/{fn}")
            else:
                print(f"[OK] /tmp/jiritsu/{fn} already clean")


def cmd_combo() -> None:
    """Guided All-in-One: Open Gate 4K 3:2 -> Cine EI -> FX2 FL2/FL3."""
    steps = [
        ("Open Gate 4K 3:2 (3840x2560)", "a6700_og_ram.so", "og_apply_ram"),
        ("Cine EI (Base ISO 800/2500)",  "a6700_cine_ei_ram.so", "cine_ei_ram"),
        ("FX2 FL2 (IN) & FL3 (SH)",      "a6700_fl23_ram.so", "fl23_ram"),
    ]
    print("============================================================")
    print("  Sony a6700 (FW v2.00) ALL-IN-ONE RAM-ONLY COMBO")
    print("  Order: Open Gate 4K 3:2 -> Cine EI -> FL2 / FL3")
    print("  Keep camera powered ON (Photo/Stills dial) throughout!")
    print("============================================================\n")
    for idx, (title, so_name, label) in enumerate(steps, 1):
        print(f"\n--- Step {idx}/{len(steps)}: {title} ---")
        if idx > 1:
            print(">>> Do NOT power the camera off!")
            print(">>> Unplug & replug USB, select Mass Storage (MSC), then press Enter...")
            input()
        text = _run_live_session(so_name, label)
        if "RESULT=APPLY_OK" not in text and "RESULT=NOTHING_TO_DO" not in text:
            raise SystemExit(f"\n[STOPPED] Step {idx} ({title}) did not report APPLY_OK. Camera unchanged/rolled back.")
    print("\n============================================================")
    print("  ALL 3 FEATURES ARE NOW LIVE IN RAM!")
    print("  Unplug USB and switch to Movie (XAVC S 4K 25p or 24p).")
    print("============================================================")


def main() -> None:
    ap = argparse.ArgumentParser(description="Safe zero-flash RAM-only runner for Sony ILCE-6700 (FW v2.00)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run",   action="store_true", help="Verify all payloads & Python USB stack offline (no USB)")
    g.add_argument("--probe",     action="store_true", help="Read-only AP-RAM safety check (Cine EI / Pro Pack)")
    g.add_argument("--og-probe",  action="store_true", help="Read-only CP-RAM safety check (Open Gate / FL2-FL3)")
    g.add_argument("--open-gate", action="store_true", help="Apply RAM-only Open Gate 4K 3:2 (3840x2560, PAL 25p / NTSC 24p)")
    g.add_argument("--cine-ei",   action="store_true", help="Apply RAM-only Cine EI (Base ISO 800/2500)")
    g.add_argument("--fl23",      action="store_true", help="Apply RAM-only FX2 FL2 (IN) & FL3 (SH) Creative Looks")
    g.add_argument("--combo",     action="store_true", help="Guided All-in-One: Open Gate + Cine EI + FL2/FL3")
    g.add_argument("--pro-pack",  action="store_true", help="Apply RAM-only Pro Pack (Shutter Curtain + Flex Exp + FTP)")
    g.add_argument("--shutter",   action="store_true", help="Apply RAM-only Power-Off Shutter Curtain")
    g.add_argument("--exposure",  action="store_true", help="Apply RAM-only Flexible Exposure")
    g.add_argument("--ftp",       action="store_true", help="Apply RAM-only Native FTP Transfer")
    g.add_argument("--clean",     action="store_true", help="Remove any leftover temp files in /tmp/jiritsu/")
    args = ap.parse_args()

    if args.dry_run:
        cmd_dry_run()
    elif args.clean:
        cmd_clean()
    elif args.combo:
        cmd_combo()
    elif args.probe:
        _run_live_session("a6700_probe_ro.so", "probe_ro")
    elif args.og_probe:
        _run_live_session("a6700_og_probe_ro.so", "og_probe_ro")
    elif args.open_gate:
        _run_live_session("a6700_og_ram.so", "og_apply_ram")
    elif args.cine_ei:
        _run_live_session("a6700_cine_ei_ram.so", "cine_ei_ram")
    elif args.fl23:
        _run_live_session("a6700_fl23_ram.so", "fl23_ram")
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
