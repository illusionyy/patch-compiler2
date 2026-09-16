#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path

import pefile

import patchfmt
import symres

CC = os.environ.get("PC2_CC", "clang")
LLD = os.environ.get("PC2_LLD", "ld.lld")
LLD_LINK = os.environ.get("PC2_LLD_LINK", "lld-link")
OBJCOPY = os.environ.get("PC2_OBJCOPY", "objcopy")
NM = os.environ.get("PC2_NM", "nm")

TARGET_TRIPLE = "i386-pc-win32"
LINK_FLAGS = [
    "/machine:x86", "/noentry", "/dll", "/force:unresolved",
    "/align:1", "/filealign:1", "/safeseh:no",
]
dummy_BASE = 0x10000000


ADDR_RE = re.compile(r'^\s*\.addr\s+(\S.*?)\s*$')
FRIENDLY_RE = re.compile(r'^\s*\.friendly\s+"([^"]*)"\s*$')
PATCH_RE = re.compile(r'^\s*\.patch\s*$')
CODE_RE = re.compile(r'^\s*\.code\s*$')
MAIN_RE = re.compile(r'^\s*\.main\s*$')
META_RE = re.compile(r'^\s*\.patch_(title|note|author|version|name|app_elf)\s+"([^"]*)"\s*$')
TITLEID_RE = re.compile(r'^\s*\.patch_titleid\s+"([^"]*)"\s*$')
APPVER_RE = re.compile(r'^\s*\.patch_app_ver\s+"([^"]*)"\s*$')
SECTION_BASE_RE = re.compile(r'^\s*\.patch_(rodata_base|data_base)\s+(\S+)\s*$')

PKG_META_KEYS = ("title", "note", "author", "version", "name", "app_elf")


def slugify(s):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', s).strip('_') or "pkg"


def split_blocks(lines, source_name="<input>"):
    blocks = []
    cur_addr = None
    cur_friendly = None
    cur_lines = []
    preamble = []
    has_main = False

    for raw in lines:
        if MAIN_RE.match(raw):
            if has_main:
                sys.exit(f"error: {source_name}: .main declared more than once")
            has_main = True
            continue
        m = ADDR_RE.match(raw)
        if m:
            if cur_addr is not None:
                blocks.append({"addr": cur_addr, "lines": cur_lines, "friendly": cur_friendly})
            cur_addr = m.group(1).split("#", 1)[0].split(";", 1)[0].strip()
            cur_friendly = None
            cur_lines = []
            continue
        if cur_addr is None:
            stripped = raw.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith(";"):
                sys.exit(f"error: {source_name}: line before first .addr is not a comment: {raw!r}")
            preamble.append(raw)
            continue
        fm = FRIENDLY_RE.match(raw)
        if fm and not cur_lines:
            cur_friendly = fm.group(1)
            continue
        cur_lines.append(raw)

    if cur_addr is not None:
        blocks.append({"addr": cur_addr, "lines": cur_lines, "friendly": cur_friendly})
    elif not blocks:
        sys.exit(f"error: {source_name}: no .addr blocks found")

    return preamble, blocks, has_main


def parse_packages(path):
    text = Path(path).read_text().splitlines()

    if not any(PATCH_RE.match(l) for l in text):
        preamble, blocks, has_main = split_blocks(text, source_name=str(path))
        pkg = {k: None for k in PKG_META_KEYS}
        pkg.update(title_id=[], app_ver=[], index=0, legacy=True, preamble=preamble, blocks=blocks,
                   has_main=has_main, rodata_base=None, data_base=None)
        return [pkg]

    packages = []
    cur = None
    body_lines = []
    in_code = False
    pkg_index = 0
    file_title_id = []

    def finalize():
        preamble, blocks, has_main = split_blocks(body_lines, source_name=f"{path} (.patch #{cur['index']})")
        cur["preamble"] = preamble
        cur["blocks"] = blocks
        cur["has_main"] = has_main
        packages.append(cur)

    for raw in text:
        if PATCH_RE.match(raw):
            if cur is not None:
                finalize()
            cur = {k: None for k in PKG_META_KEYS}
            cur.update(title_id=[], app_ver=[], index=pkg_index, legacy=False,
                       rodata_base=None, data_base=None)
            pkg_index += 1
            body_lines = []
            in_code = False
            continue
        if cur is None:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            tm = TITLEID_RE.match(raw)
            if tm:
                file_title_id.append(tm.group(1))
                continue
            sys.exit(f"error: {path}: line before first .patch is not a comment "
                     f"or .patch_titleid: {raw!r}")
        if in_code:
            body_lines.append(raw)
            continue
        if CODE_RE.match(raw):
            in_code = True
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if TITLEID_RE.match(raw):
            sys.exit(f"error: {path}: .patch_titleid must be declared once before the "
                     f"first .patch block, not inside .patch package #{cur['index']}: {raw!r}")
        vm = APPVER_RE.match(raw)
        if vm:
            cur["app_ver"].append(vm.group(1))
            continue
        mm = META_RE.match(raw)
        if mm:
            cur[mm.group(1)] = mm.group(2)
            continue
        sm = SECTION_BASE_RE.match(raw)
        if sm:
            try:
                cur[sm.group(1)] = int(sm.group(2), 0)
            except ValueError:
                sys.exit(f"error: {path}: bad address in {raw!r}")
            continue
        sys.exit(f"error: {path}: unrecognized metadata line before .code: {raw!r}")

    if cur is None:
        sys.exit(f"error: {path}: no .patch package found")
    if not in_code:
        sys.exit(f"error: {path}: .patch package #{cur['index']} has no .code section")
    finalize()

    for pkg in packages:
        pkg["title_id"] = file_title_id

    main_pkgs = [pkg for pkg in packages if pkg["has_main"]]
    if len(main_pkgs) > 1:
        where = ", ".join(f"#{pkg['index']} ({pkg['title'] or 'untitled'})" for pkg in main_pkgs)
        sys.exit(f"error: {path}: .main declared in more than one .patch package: {where}")

    return packages


def check_block_overlap(blocks):
    ends = sorted((b["addr"], b["addr"]) for b in blocks)
    for (a_addr, _), (b_addr, _) in zip(ends, ends[1:]):
        if a_addr == b_addr:
            sys.exit(f"error: two .addr blocks start at the same address 0x{a_addr:x}")


def label_offsets(obj_path, labels):
    out = subprocess.run([NM, "--defined-only", str(obj_path)], check=True,
                          capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            value, _kind, name = parts
            found[name] = int(value, 16)
    return {name: found[name] for name in labels if name in found}


def label_line_groups(lines):
    groups = {}
    cur_name = None
    cur_lines = []
    for raw in lines:
        code = raw.split("#", 1)[0].split(";", 1)[0]
        m = patchfmt.LABEL_RE.match(code)
        if m and m.group(1)[0] != "." and not m.group(1)[0].isdigit():
            if cur_name is not None:
                groups[cur_name] = cur_lines
            cur_name = m.group(1)
            cur_lines = []
            continue
        stripped = raw.strip()
        if cur_name is not None and stripped:
            cur_lines.append(stripped)
    if cur_name is not None:
        groups[cur_name] = cur_lines
    return groups


def split_block_data(addr, data, lines, obj_path, label):
    labels = patchfmt.block_labels(lines)
    if not labels:
        return [(addr, data, label)]
    offsets = label_offsets(obj_path, labels)
    boundaries = sorted(set(offsets.values()))
    if not boundaries:
        return [(addr, data, label)]
    if boundaries[0] != 0:
        boundaries = [0] + boundaries
    names_by_offset = {}
    for name, off in offsets.items():
        names_by_offset.setdefault(off, name)
    groups = label_line_groups(lines)

    out = []
    for i, start in enumerate(boundaries):
        end = boundaries[i + 1] if i + 1 < len(boundaries) else len(data)
        if end <= start:
            continue
        name = names_by_offset.get(start)
        if name is None:
            out.append((addr + start, data[start:end], label))
        else:
            detail = "; ".join(groups.get(name, []))
            sub_label = f"{label}:{name}" + (f" ({detail})" if detail else "")
            out.append((addr + start, data[start:end], sub_label))
    return out


def assemble_and_link(blocks, preamble, syms, outdir: Path, tag: str, label: str):
    outdir.mkdir(parents=True, exist_ok=True)
    preamble = patchfmt.default_syntax_preamble(preamble) + preamble

    all_syms = dict(syms)
    rewritten_blocks = []
    for blk in blocks:
        new_lines, literal_syms = patchfmt.dodge_literal_jump_targets(blk["lines"])
        all_syms.update(literal_syms)
        rewritten_blocks.append({**blk, "lines": new_lines})
    blocks = rewritten_blocks

    objs = []
    section_names = []
    for i, blk in enumerate(blocks):
        secname = f".pblk{i}"
        section_names.append(secname)
        src = outdir / f"{tag}_{i:02d}.s"
        body = "\n".join(preamble + [f'.section {secname},"ax"'] + blk["lines"])
        src.write_text(body + "\n")
        obj = outdir / f"{tag}_{i:02d}.o"
        patchfmt.run([CC, "-c", src, "-o", obj])
        objs.append(obj)

    linked = outdir / f"{tag}_linked.o"
    ldflags = ["-e", "0", "--unresolved-symbols=ignore-all", "--noinhibit-exec"]
    for i, blk in enumerate(blocks):
        ldflags.append(f"--section-start={section_names[i]}={hex(blk['addr'])}")
    for name, addr in all_syms.items():
        ldflags.append(f"--defsym={name}=0x{addr:x}")

    link_log = outdir / f"{tag}_link.log"
    patchfmt.run([LLD, *objs, "-o", linked, *ldflags], log_path=link_log)

    chunks = []
    options = []
    for i, blk in enumerate(blocks):
        secname = section_names[i]
        addr = blk["addr"]
        raw_bin = outdir / f"{tag}_{i:02d}.bin"
        patchfmt.run([OBJCOPY, f"--only-section={secname}", "-O", "binary", linked, raw_bin])
        data = raw_bin.read_bytes()
        if data:
            for sub_addr, sub_data, sub_label in split_block_data(addr, data, blk["lines"], objs[i], label):
                chunks.append(patchfmt.make_chunk(sub_addr, sub_data, label=sub_label))
            if i + 1 < len(blocks):
                next_addr = blocks[i + 1]["addr"]
                end = addr + len(data)
                if end > next_addr:
                    print(f"warning: block at 0x{addr:x} runs to 0x{end:x}, "
                          f"past the next .addr 0x{next_addr:x}")

            info = blk["info"]
            if info is not None:
                if len(data) < info["size"]:
                    print(f"warning: block at 0x{addr:x} resolved as {info['struct']}.{info['member']} "
                          f"but only produced {len(data)} byte(s), need {info['size']} - skipping "
                          f"options-catalog entry")
                else:
                    value = int.from_bytes(data[:info["size"]], "little")
                    friendly = blk["friendly"] or f"{info['struct']}.{info['member']}"
                    options.append({
                        "struct": info["struct"],
                        "member": info["member"],
                        "addr": addr,
                        "size": info["size"],
                        "value": value,
                        "friendly": friendly,
                    })
    return chunks, options


def assemble_and_link_pe32(blocks, preamble, syms, outdir: Path, tag: str, label: str):
    outdir.mkdir(parents=True, exist_ok=True)
    preamble = patchfmt.default_syntax_preamble(preamble) + preamble

    all_syms = dict(syms)
    rewritten_blocks = []
    for blk in blocks:
        new_lines, literal_syms = patchfmt.dodge_literal_jump_targets(blk["lines"])
        all_syms.update(literal_syms)
        rewritten_blocks.append({**blk, "lines": new_lines})
    blocks = rewritten_blocks

    abs_obj = outdir / f"{tag}_abs_syms.o"
    abs_obj.write_bytes(symres.build_absolute_symbols_obj(all_syms))

    chunks = []
    options = []
    for i, blk in enumerate(blocks):
        secname = f".pblk{i}"
        addr = blk["addr"]

        src = outdir / f"{tag}_{i:02d}.s"
        body = "\n".join(preamble + [f'.section {secname},"xr"'] + blk["lines"])
        src.write_text(body + "\n")
        obj = outdir / f"{tag}_{i:02d}.o"
        patchfmt.run([CC, f"--target={TARGET_TRIPLE}", "-c", src, "-o", obj])

        dummy_dll = outdir / f"{tag}_{i:02d}.dummy.dll"
        patchfmt.run([LLD_LINK, obj, abs_obj, *LINK_FLAGS,
                      f"/base:0x{dummy_BASE:x}", f"/out:{dummy_dll}"])
        dummy_pe = pefile.PE(str(dummy_dll))
        dummy_sections = symres.coff_sections(dummy_pe)
        sec = dummy_sections.get(secname)
        if sec is None or sec.Misc_VirtualSize == 0:
            continue
        rva = sec.VirtualAddress
        real_base = addr - rva

        linked = outdir / f"{tag}_{i:02d}.dll"
        patchfmt.run([LLD_LINK, obj, abs_obj, *LINK_FLAGS,
                      f"/base:0x{real_base:x}", f"/out:{linked}"])
        pe = pefile.PE(str(linked))
        sec = symres.coff_sections(pe).get(secname)
        vsize = sec.Misc_VirtualSize
        data = symres.raw_section_bytes(pe, sec)[:vsize]
        if len(data) < vsize:
            data += b"\x00" * (vsize - len(data))

        if data:
            for sub_addr, sub_data, sub_label in split_block_data(addr, data, blk["lines"], obj, label):
                chunks.append(patchfmt.make_chunk(sub_addr, sub_data, label=sub_label))
            if i + 1 < len(blocks):
                next_addr = blocks[i + 1]["addr"]
                end = addr + len(data)
                if end > next_addr:
                    print(f"warning: block at 0x{addr:x} runs to 0x{end:x}, "
                          f"past the next .addr 0x{next_addr:x}")

            info = blk["info"]
            if info is not None:
                if len(data) < info["size"]:
                    print(f"warning: block at 0x{addr:x} resolved as {info['struct']}.{info['member']} "
                          f"but only produced {len(data)} byte(s), need {info['size']} - skipping "
                          f"options-catalog entry")
                else:
                    value = int.from_bytes(data[:info["size"]], "little")
                    friendly = blk["friendly"] or f"{info['struct']}.{info['member']}"
                    options.append({
                        "struct": info["struct"],
                        "member": info["member"],
                        "addr": addr,
                        "size": info["size"],
                        "value": value,
                        "friendly": friendly,
                    })
    return chunks, options

