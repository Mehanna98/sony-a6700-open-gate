#!/usr/bin/env python3
"""build.py -- Cross-compile freestanding AArch64 Jiritsu .so modules via Zig.

Usage:
  Set ZIG_EXE env var or have `zig` (v0.13.0+) on PATH, then run:
      python src/build.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SRC_DIR.parent
OUT_DIR = REPO_ROOT / "payloads"

ZIG_BIN = os.environ.get("ZIG_EXE") or shutil.which("zig")

TARGETS = [
    ("a6700_probe_ro",     SRC_DIR / "a6700_probe_ro.c",     OUT_DIR / "a6700_probe_ro.so",     []),
    ("a6700_cine_ei_ram",  SRC_DIR / "a6700_cine_ei_ram.c",  OUT_DIR / "a6700_cine_ei_ram.so",  []),
    ("a6700_features_ram", SRC_DIR / "a6700_features_ram.c", OUT_DIR / "a6700_features_ram.so", ["-DFEAT_MASK=7"]),
    ("a6700_shutter_ram",  SRC_DIR / "a6700_features_ram.c", OUT_DIR / "a6700_shutter_ram.so",  ["-DFEAT_MASK=1"]),
    ("a6700_exposure_ram", SRC_DIR / "a6700_features_ram.c", OUT_DIR / "a6700_exposure_ram.so", ["-DFEAT_MASK=2"]),
    ("a6700_ftp_ram",      SRC_DIR / "a6700_features_ram.c", OUT_DIR / "a6700_ftp_ram.so",      ["-DFEAT_MASK=4"]),
    ("a6700_fl23_ram",     SRC_DIR / "a6700_fl23_ram.c",     OUT_DIR / "a6700_fl23_ram.so",     []),
    ("a6700_og_probe_ro",  SRC_DIR / "a6700_og_probe_ro.c",  OUT_DIR / "a6700_og_probe_ro.so",  []),
    ("a6700_og_ram",       SRC_DIR / "a6700_og_ram.c",       OUT_DIR / "a6700_og_ram.so",       []),
]


def compile_one(zig: str, name: str, src: Path, out: Path, extra_cflags: list[str]) -> dict:
    obj = OUT_DIR / f"{name}.o"
    cc_cmd = [
        zig, "cc",
        "-target", "aarch64-linux-gnu",
        "-O2",
        "-Wall", "-Wextra", "-Werror",
        "-fPIC",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-mno-outline-atomics",
        "-fvisibility=hidden",
        f"-I{SRC_DIR}",
        *extra_cflags,
        "-c", str(src),
        "-o", str(obj),
    ]
    ld_cmd = [
        zig, "ld.lld",
        "-shared",
        "-init", "_init",
        "-z", "defs",
        "--no-undefined",
        "--build-id=none",
        "-z", "max-page-size=4096",
        "--strip-all",
        str(obj),
        "-o", str(out),
    ]
    print(f"[BUILD] {name} -> {out.name}")
    res = subprocess.run(cc_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr)
        raise SystemExit(f"Compile failed for {name} (rc={res.returncode})")
    res2 = subprocess.run(ld_cmd, capture_output=True, text=True)
    if obj.exists():
        obj.unlink()
    if res2.returncode != 0:
        print(res2.stdout)
        print(res2.stderr)
        raise SystemExit(f"Link failed for {name} (rc={res2.returncode})")
    data = out.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    print(f"  [OK] {out.name}: {len(data):,} bytes (< 65,536 limit), sha256={sha}")
    assert len(data) < 65536, f"{out.name} exceeds Jiritsu 65536 B limit!"
    return {"name": name, "file": out.name, "size": len(data), "sha256": sha}


def main() -> None:
    if not ZIG_BIN:
        raise SystemExit("Zig compiler not found. Install Zig 0.13+ or set ZIG_EXE=/path/to/zig")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"compiler": Path(ZIG_BIN).name, "target": "aarch64-linux-gnu", "modules": []}
    for name, src, out, extra in TARGETS:
        manifest["modules"].append(compile_one(ZIG_BIN, name, src, out, extra))
    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Wrote {OUT_DIR / 'manifest.json'}")


if __name__ == "__main__":
    main()
