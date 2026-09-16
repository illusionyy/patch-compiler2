#!/usr/bin/env python3
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

import dump
import patchfmt
import symres

PE32_SECTIONS = (".text", ".rdata", ".data", ".bss")


def pe32_section_ranges(pe):
    sections = symres.coff_sections(pe)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ranges = {}
    for name in PE32_SECTIONS:
        sec = sections.get(name)
        if sec is None:
            continue
        vsize = sec.Misc_VirtualSize
        if vsize == 0:
            continue
        addr = image_base + sec.VirtualAddress
        ranges[name] = (addr, addr + vsize, sec)
    return ranges


def split_pe32_data_chunks(pe_path):
    pe = pefile.PE(str(pe_path))
    ranges = pe32_section_ranges(pe)
    syms = symres.read_pe_symbols(pe_path)

    names_by_addr = {}
    for name, addr in syms.items():
        names_by_addr.setdefault(addr, name)

    chunks = []
    for name in (".rdata", ".data", ".bss"):
        if name not in ranges:
            continue
        addr0, addr1, sec = ranges[name]
        vsize = addr1 - addr0
        raw = symres.raw_section_bytes(pe, sec)
        if len(raw) < vsize:
            raw += b"\x00" * (vsize - len(raw))
        else:
            raw = raw[:vsize]
        sec_name = name.lstrip(".")
        sec_addrs = sorted({a for a in syms.values() if addr0 <= a < addr1})

        def gap_chunk(addr, size):
            chunks.append(patchfmt.make_chunk(
                addr, raw[addr - addr0: addr - addr0 + size], label=f"{sec_name}:<gap>"))

        cursor = addr0
        for i, addr in enumerate(sec_addrs):
            if addr > cursor:
                gap_chunk(cursor, addr - cursor)
            end = sec_addrs[i + 1] if i + 1 < len(sec_addrs) else addr1
            size = end - addr
            data = raw[addr - addr0: addr - addr0 + size]
            chunks.append(patchfmt.make_chunk(addr, data, label=f"{sec_name}:{names_by_addr.get(addr, '?')}"))
            cursor = end
        if cursor < addr1:
            gap_chunk(cursor, addr1 - cursor)
    return chunks


def extract_pe32_split(pe_path, objdump):
    chunks = split_text_chunks(pe_path, objdump)
    chunks += split_pe32_data_chunks(pe_path)
    return chunks


def split_text_chunks(elf_path, objdump):
    chunks = []
    objdump_out = dump.run_objdump(elf_path, objdump, None, "intel", True, False)
    for section, func, addr, byte_str, text in dump.parse_instructions(objdump_out):
        raw = bytes.fromhex(byte_str.replace(" ", ""))
        label = f"{section.lstrip('.')}:{func + ':' if func else ''}{text}"
        chunks.append(patchfmt.make_chunk(addr, raw, label=label))
    return chunks


def data_symbols_for_section(symtab, shndx):
    syms = [
        s for s in symtab.iter_symbols()
        if s.name
        and s["st_info"]["type"] in ("STT_OBJECT", "STT_NOTYPE")
        and s["st_shndx"] == shndx
        and (s["st_size"] > 0 or s["st_value"] > 0)
    ]
    syms.sort(key=lambda s: (s["st_value"], -s["st_size"]))
    seen = set()
    out = []
    for s in syms:
        key = (s["st_value"], s["st_size"])
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def split_data_chunks(elf_path):
    chunks = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return chunks

        for idx, sec in enumerate(elf.iter_sections()):
            flags = sec["sh_flags"]
            if not (flags & SH_FLAGS.SHF_ALLOC) or (flags & SH_FLAGS.SHF_EXECINSTR):
                continue
            if sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
                continue
            if sec["sh_size"] == 0:
                continue

            is_bss = sec["sh_type"] == "SHT_NOBITS"
            sec_addr = sec["sh_addr"]
            sec_name = sec.name.lstrip(".")
            raw = b"" if is_bss else sec.data()
            syms = data_symbols_for_section(symtab, idx)

            def gap_chunk(addr, size):
                data = b"\x00" * size if is_bss else raw[addr - sec_addr: addr - sec_addr + size]
                chunks.append(patchfmt.make_chunk(addr, data, label=f"{sec_name}:<gap>"))

            cursor = sec_addr
            for sym in syms:
                addr, size = sym["st_value"], sym["st_size"] or 1
                if addr > cursor:
                    gap_chunk(cursor, addr - cursor)
                data = b"\x00" * size if is_bss else raw[addr - sec_addr: addr - sec_addr + size]
                chunks.append(patchfmt.make_chunk(addr, data, label=f"{sec_name}:{sym.name}"))
                cursor = addr + size

            sec_end = sec_addr + sec["sh_size"]
            if cursor < sec_end:
                gap_chunk(cursor, sec_end - cursor)
    return chunks


def extract_split(elf_path, objdump):
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        has_text = any(
            (sec["sh_flags"] & SH_FLAGS.SHF_ALLOC) and (sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR)
            and sec["sh_size"] > 0
            for sec in elf.iter_sections()
        )
    chunks = []
    if has_text:
        chunks += split_text_chunks(elf_path, objdump)
    chunks += split_data_chunks(elf_path)
    return chunks

