#!/usr/bin/env python3
import io
import re
import struct
import subprocess
from pathlib import Path

import pefile
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo, DwarfConfig, DebugSectionDescriptor

import dump

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

COFF_SYMBOL_RECORD_SIZE = 18


def detect_format(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head.startswith(ELF_MAGIC):
        return "elf"
    if head[:2] == PE_MAGIC:
        return "pe"
    raise SystemExit(f"error: unrecognized object format: {path}")


def coff_sections(pe):
    data = pe.__data__
    fh = pe.FILE_HEADER
    strtab = b""
    if fh.PointerToSymbolTable:
        off = fh.PointerToSymbolTable + fh.NumberOfSymbols * COFF_SYMBOL_RECORD_SIZE
        size = int.from_bytes(data[off:off + 4], "little")
        strtab = data[off:off + size]

    def resolve_name(raw8):
        if raw8[0:1] == b"/":
            off = int(raw8.rstrip(b"\x00").decode()[1:])
            end = strtab.index(b"\x00", off)
            return strtab[off:end].decode()
        return raw8.rstrip(b"\x00").decode()

    return {resolve_name(s.Name): s for s in pe.sections}


def raw_section_bytes(pe, section):
    data = pe.__data__
    start = section.PointerToRawData
    return bytes(data[start:start + section.SizeOfRawData])


IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_SYM_ABSOLUTE = -1
IMAGE_SYM_CLASS_EXTERNAL = 2
COFF_FILE_HEADER_SIZE = 20


def build_absolute_symbols_obj(syms, prefix=""):
    strtab_entries = []
    strtab_offset = 4
    sym_records = []
    for name, value in syms.items():
        raw = (prefix + name).encode("ascii")
        if len(raw) <= 8:
            name_field = raw.ljust(8, b"\x00")
        else:
            name_field = struct.pack("<II", 0, strtab_offset)
            strtab_entries.append(raw + b"\x00")
            strtab_offset += len(raw) + 1
        sym_records.append(struct.pack(
            "<8sIhHBB", name_field, value & 0xFFFFFFFF,
            IMAGE_SYM_ABSOLUTE, 0, IMAGE_SYM_CLASS_EXTERNAL, 0,
        ))

    symtab = b"".join(sym_records)
    strtab = struct.pack("<I", strtab_offset) + b"".join(strtab_entries)
    header = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_I386, 0, 0,
        COFF_FILE_HEADER_SIZE, len(syms), 0, 0,
    )
    return header + symtab + strtab


def read_elf_symbols(path):
    out = subprocess.run(["nm", "--defined-only", "--extern-only", str(path)],
                          check=True, capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            addr, _kind, name = parts
            syms[name] = int(addr, 16)
    return syms


MAP_ROW_RE = re.compile(r'^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{8,16})\s+\S')


def read_pe_symbols(path):
    map_path = Path(str(path) + ".map")
    if not map_path.exists():
        raise SystemExit(
            f"error: {map_path} not found - pe32 symbol sources need the "
            f".map file build_patch.py writes next to its linked output"
        )
    syms = {}
    for line in map_path.read_text().splitlines():
        m = MAP_ROW_RE.match(line)
        if not m:
            continue
        name, addr = m.group(1), m.group(2)
        if name.startswith("_"):
            name = name[1:]
        syms[name] = int(addr, 16)
    return syms


def elf_dwarf_var_types(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        return dump.dwarf_global_var_types(elf)


def pe_dwarf_var_types(path):
    pe = pefile.PE(str(path))
    sections = coff_sections(pe)

    def sec(name):
        s = sections.get(name)
        if s is None:
            return None
        raw = raw_section_bytes(pe, s)
        return DebugSectionDescriptor(io.BytesIO(raw), name, 0, len(raw), 0)

    config = DwarfConfig(little_endian=True, default_address_size=4, machine_arch="x86")
    dwarfinfo = DWARFInfo(
        config=config,
        debug_info_sec=sec(".debug_info"),
        debug_aranges_sec=sec(".debug_aranges"),
        debug_abbrev_sec=sec(".debug_abbrev"),
        debug_frame_sec=None,
        eh_frame_sec=None,
        debug_str_sec=sec(".debug_str"),
        debug_loc_sec=sec(".debug_loc"),
        debug_ranges_sec=sec(".debug_ranges"),
        debug_line_sec=sec(".debug_line"),
        debug_pubtypes_sec=None,
        debug_pubnames_sec=None,
        debug_addr_sec=None,
        debug_str_offsets_sec=None,
        debug_line_str_sec=sec(".debug_line_str"),
        debug_loclists_sec=None,
        debug_rnglists_sec=None,
        debug_sup_sec=None,
        gnu_debugaltlink_sec=None,
        debug_types_sec=None,
    )
    types = {}
    try:
        for cu in dwarfinfo.iter_CUs():
            top = cu.get_top_DIE()
            for die in top.iter_children():
                if die.tag != "DW_TAG_variable":
                    continue
                ext = die.attributes.get("DW_AT_external")
                if ext is None or ext.value != 1:
                    continue
                name = dump._attr_str(die, "DW_AT_name")
                if not name or "DW_AT_type" not in die.attributes:
                    continue
                types[name] = dump.strip_typedefs(die.get_DIE_from_attribute("DW_AT_type"))
    except Exception:
        pass
    return types


def member_chain_offset(type_die, parts):
    offset = 0
    die = type_die
    for part in parts:
        if die is None or die.tag not in dump.AGGREGATE_TAGS:
            raise ValueError(f"'{part}' is not a member of a struct/union")
        found = None
        for member in die.iter_children():
            if member.tag == "DW_TAG_member" and dump._attr_str(member, "DW_AT_name") == part:
                found = member
                break
        if found is None:
            names = [dump._attr_str(m, "DW_AT_name") for m in die.iter_children()
                      if m.tag == "DW_TAG_member"]
            raise ValueError(f"no member '{part}', have: {', '.join(n for n in names if n)}")
        loc = found.attributes.get("DW_AT_data_member_location")
        moff = loc.value if (loc is not None and isinstance(loc.value, int)) else 0
        offset += moff
        if "DW_AT_type" not in found.attributes:
            raise ValueError(f"member '{part}' has no type info")
        die = dump.strip_typedefs(found.get_DIE_from_attribute("DW_AT_type"))
    return offset, dump.die_byte_size(die), dump.die_type_name(die)


DOTTED_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$')
BARE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


class SymbolTable:

    def __init__(self, obj_paths):
        self.syms = {}
        self.var_types = {}
        for obj in obj_paths:
            fmt = detect_format(obj)
            if fmt == "elf":
                self.syms.update(read_elf_symbols(obj))
                self.var_types.update(elf_dwarf_var_types(obj))
            else:
                self.syms.update(read_pe_symbols(obj))
                self.var_types.update(pe_dwarf_var_types(obj))

    def resolve(self, expr):
        expr = expr.strip()

        if DOTTED_RE.match(expr):
            base, *members = expr.split(".")
            if base not in self.syms:
                raise SystemExit(f"error: unknown symbol '{base}' in '{expr}'")
            type_die = self.var_types.get(base)
            if type_die is None:
                raise SystemExit(
                    f"error: no DWARF struct layout for '{base}' (needs to be a "
                    f"global, external variable in an object compiled with -g)"
                )
            try:
                offset, size, type_name = member_chain_offset(type_die, members)
            except ValueError as e:
                raise SystemExit(f"error: resolving '{expr}': {e}")
            info = {"struct": base, "member": ".".join(members), "offset": offset,
                    "size": size, "type": type_name}
            return self.syms[base] + offset, info

        if BARE_RE.match(expr) and expr in self.syms:
            return self.syms[expr], None

        try:
            return int(expr, 0), None
        except ValueError:
            raise SystemExit(f"error: unresolved .addr expression '{expr}' "
                              f"(not a known symbol and not a numeric literal)")

