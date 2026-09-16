#!/usr/bin/env python3
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pefile

import patchfmt
import symres

CC = os.environ.get("PC2_CC", "clang")
CXX = os.environ.get("PC2_CXX", "clang++")
LLD = os.environ.get("PC2_LLD", "ld.lld")
LLD_LINK = os.environ.get("PC2_LLD_LINK", "lld-link")

CFLAGS = [
    "-g",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-asynchronous-unwind-tables",
    "-fplt",
    "-fno-jump-tables",
    "-fno-inline",
    "-ffreestanding",
    "-gdwarf-4",
    "-fno-builtin",
    "-nostdlib",
    "-fvisibility-from-dllstorageclass",
    "-fvisibility-nodllstorageclass=default",
    "-fvisibility-externs-nodllstorageclass=hidden",
] + shlex.split(os.environ.get("PC2_EXTRA_CFLAGS", ""))

TARGET_TRIPLE = "i386-pc-win32"

LDFLAGS = [
    "--icf=all", "-e", "0",
    "--unresolved-symbols=ignore-all", "--noinhibit-exec",
]
LINK_FLAGS = [
    "/machine:x86", "/noentry", "/dll",
    "/align:1", "/filealign:1", "/safeseh:no", "/debug:dwarf",
]

SECTIONS_TO_KEEP = [".text", ".rodata", ".data"]

MERGE_BSS_SCRIPT = """SECTIONS {
  .rodata : { *(.rodata .rodata.*) }
}
INSERT AFTER .text;
SECTIONS {
  .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) }
}
INSERT AFTER .rodata;
"""

C_EXTS = {".c"}
CXX_EXTS = {".cc", ".cpp", ".cxx"}
ASM_EXTS = {".s", ".asm"}


def intel_syntax_source(src: Path, obj: Path) -> Path:
    lines = src.read_text().splitlines()
    preamble = patchfmt.default_syntax_preamble(lines)
    if not preamble:
        return src
    wrapped = obj.with_name(obj.stem + ".intel" + src.suffix)
    wrapped.write_text("\n".join(preamble + lines) + "\n")
    return wrapped


def compile_one(src: Path, obj: Path) -> Path:
    ext = src.suffix.lower()
    if ext in C_EXTS:
        patchfmt.run([CC, *CFLAGS, "-c", src, "-o", obj])
    elif ext in CXX_EXTS:
        patchfmt.run([CXX, *CFLAGS, "-c", src, "-o", obj])
    elif ext in ASM_EXTS:
        patchfmt.run([CC, "-c", intel_syntax_source(src, obj), "-o", obj])
    elif ext == ".o":
        return src
    else:
        sys.exit(f"error: don't know how to compile {src} (unknown extension {ext!r})")
    return obj


def compile_sources(srcs, outdir: Path):
    objs = []
    for i, s in enumerate(srcs):
        src = Path(s)
        if not src.exists():
            sys.exit(f"error: source file not found: {src}")
        obj = outdir / f"{i:02d}_{src.stem}.o"
        objs.append(compile_one(src, obj))
    return objs


def compile_one_pe32(src: Path, obj: Path) -> Path:
    ext = src.suffix.lower()
    target = [f"--target={TARGET_TRIPLE}"]
    if ext in C_EXTS:
        patchfmt.run([CC, *target, *CFLAGS, "-c", src, "-o", obj])
    elif ext in CXX_EXTS:
        patchfmt.run([CXX, *target, *CFLAGS, "-c", src, "-o", obj])
    elif ext in ASM_EXTS:
        patchfmt.run([CC, *target, "-c", intel_syntax_source(src, obj), "-o", obj])
    elif ext == ".o":
        return src
    else:
        sys.exit(f"error: don't know how to compile {src} (unknown extension {ext!r})")
    return obj


def compile_sources_pe32(srcs, outdir: Path):
    objs = []
    for i, s in enumerate(srcs):
        src = Path(s)
        if not src.exists():
            sys.exit(f"error: source file not found: {src}")
        obj = outdir / f"{i:02d}_{src.stem}.o"
        objs.append(compile_one_pe32(src, obj))
    return objs


def run_ld(objs, outdir: Path, script: Path, bases: dict, icf_report: Path, out: Path, defsyms=None):
    ldflags = list(LDFLAGS) + ["-T", script]
    for name, base in bases.items():
        if base is not None:
            ldflags.append(f"--section-start={name}={hex(base)}")
    for name, addr in (defsyms or {}).items():
        ldflags.append(f"--defsym={name}=0x{addr:x}")
    cmd = [LLD, *objs, "-o", out, *ldflags, "--print-icf-sections"]
    patchfmt.run(cmd, log_path=icf_report)


def section_layout(obj: Path):
    out = subprocess.run(["readelf", "-S", "-W", str(obj)], check=True,
                          capture_output=True, text=True).stdout
    layout = {}
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+\S*\s+\S+\s+\d+\s+\d+\s+(\d+)", line)
        if m:
            name, _addr, _off, size, align = m.groups()
            layout[name] = (int(size, 16), max(1, int(align)))
    return layout


def align_up(value, align):
    if align <= 1:
        return value
    return (value + align - 1) // align * align


def resolve_bases(objs, outdir: Path, script: Path, explicit: dict, pack_base, defsyms=None):
    dummy_out = outdir / "dummy.o"
    dummy_report = outdir / "icf_report.dummy.txt"
    run_ld(objs, outdir, script, explicit, dummy_report, dummy_out, defsyms)
    layout = section_layout(dummy_out)

    bases = {}
    cursor = None
    for name in SECTIONS_TO_KEEP:
        size, align = layout.get(name, (0, 1))
        if explicit.get(name) is not None:
            base = explicit[name]
        elif cursor is None:
            base = pack_base if pack_base is not None else 0
        else:
            base = align_up(cursor, align)
        bases[name] = base
        cursor = base + size
    return bases


def link(objs, outdir: Path, text_base, rodata_base, data_base, pack_base=None, defsyms=None):
    out = outdir / "merged.o"
    script = outdir / "merge_bss.ld"
    script.write_text(MERGE_BSS_SCRIPT)

    explicit = {".text": text_base, ".rodata": rodata_base, ".data": data_base}
    bases = resolve_bases(objs, outdir, script, explicit, pack_base, defsyms)

    icf_report = outdir / "icf_report.txt"
    run_ld(objs, outdir, script, bases, icf_report, out, defsyms)

    placed = [f"{name}=0x{base:x}" for name, base in bases.items()]
    auto = [name for name, base in explicit.items() if base is None]
    detail = f"base addresses: {', '.join(placed)}"
    if auto:
        detail += f"  (auto-packed: {', '.join(auto)})"
    patchfmt.vprint(f"linked -> {out}  ({detail}, .bss merged into .data)")
    return out


def pe32_text_rva(image: Path):
    pe = pefile.PE(str(image))
    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00").decode() == ".text":
            return sec.VirtualAddress
    return 0


def link_pe32(objs, outdir: Path, text_base, defsyms=None):
    out = outdir / "merged.dll"
    map_out = outdir / "merged.dll.map"
    requested = text_base if text_base is not None else 0x10000000

    extra_objs = []
    if defsyms:
        abs_obj = outdir / "build_patch_abs_syms.o"
        abs_obj.write_bytes(symres.build_absolute_symbols_obj(defsyms))
        extra_objs.append(abs_obj)

    def do_link(image_base):
        cmd = [
            LLD_LINK, *objs, *extra_objs, *LINK_FLAGS,
            f"/base:0x{image_base:x}", f"/map:{map_out}", f"/out:{out}",
        ]
        patchfmt.run(cmd)

    do_link(requested)
    rva = pe32_text_rva(out)
    image_base = requested - rva
    if rva != 0:
        do_link(image_base)
        rva = pe32_text_rva(out)

    patchfmt.vprint(f"linked -> {out}  (.text=0x{requested:x}, image_base=0x{image_base:x}, "
                     f".map -> {map_out})")
    return out, map_out

