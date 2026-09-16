#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

import patchfmt

CC = "clang"
LLD = "ld.lld"
NM = "nm"


def literal_blocks(packages):
    out = []
    for pkg in packages:
        for blk in pkg["blocks"]:
            try:
                addr = int(blk["addr"].strip(), 0)
            except ValueError:
                continue
            labels = patchfmt.block_labels(blk["lines"])
            if labels:
                out.append({"addr": addr, "lines": blk["lines"],
                            "preamble": pkg["preamble"], "labels": labels})
    return out


def section_size(obj: Path, secname: str) -> int:
    out = subprocess.run(["readelf", "-S", "-W", str(obj)], check=True,
                          capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m and m.group(1) == secname:
            return int(m.group(4), 16)
    return 0


def label_addresses(blocks, outdir: Path, tag: str):
    outdir.mkdir(parents=True, exist_ok=True)
    result = {}
    next_free = None
    for i, blk in enumerate(blocks):
        secname = f".sym{i}"
        src = outdir / f"{tag}_sym_{i:02d}.s"
        preamble = patchfmt.default_syntax_preamble(blk["preamble"]) + blk["preamble"]
        new_lines, literal_syms = patchfmt.dodge_literal_jump_targets(blk["lines"])
        body = "\n".join(preamble + [f'.section {secname},"ax"'] + new_lines)
        src.write_text(body + "\n")
        obj = outdir / f"{tag}_sym_{i:02d}.o"
        patchfmt.run([CC, "-c", src, "-o", obj])

        linked = outdir / f"{tag}_sym_{i:02d}.linked.o"
        ldflags = ["-e", "0", "--unresolved-symbols=ignore-all", "--noinhibit-exec",
                   f"--section-start={secname}={hex(blk['addr'])}"]
        for name, value in literal_syms.items():
            ldflags.append(f"--defsym={name}=0x{value:x}")
        patchfmt.run([LLD, obj, "-o", linked, *ldflags])

        end = blk["addr"] + section_size(linked, secname)
        next_free = end if next_free is None else max(next_free, end)

        out = subprocess.run([NM, "--defined-only", str(linked)],
                              check=True, capture_output=True, text=True).stdout
        found = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:
                addr, _kind, name = parts
                found[name] = int(addr, 16)

        for name in blk["labels"]:
            if name not in found:
                sys.exit(f"error: label '{name}' at .addr {hex(blk['addr'])} produced "
                          f"no symbol (unexpected)")
            if name in result and result[name] != found[name]:
                sys.exit(f"error: label '{name}' resolves to two different addresses "
                          f"(0x{result[name]:x} and 0x{found[name]:x})")
            result[name] = found[name]
    return result, next_free
