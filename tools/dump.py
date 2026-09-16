#!/usr/bin/env python3
import re
import struct as _struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from elftools.elf.enums import ENUM_RELOC_TYPE_x64

import patchfmt

RELOC_TYPE_NAME_BY_VALUE = {v: k for k, v in ENUM_RELOC_TYPE_x64.items()}

LABEL_RE = re.compile(r'^([0-9a-f]+) <([^>]+)>:$')
INSN_RE = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\t?(.*)$')

C_ESCAPES = {0x07: "\\a", 0x08: "\\b", 0x09: "\\t", 0x0a: "\\n",
             0x0b: "\\v", 0x0c: "\\f", 0x0d: "\\r", 0x22: '\\"', 0x5c: "\\\\"}


def run_objdump(path, objdump, section, syntax, symbolize, show_source):
    args = [objdump, "-d", "-r"]
    if section:
        args += ["--section", section]
    if syntax == "intel":
        args.append("--x86-asm-syntax=intel")
    if symbolize:
        args.append("--symbolize-operands")
    if show_source:
        args.append("-S")
    args.append(str(path))
    print("+", " ".join(str(a) for a in args), file=sys.stderr)
    result = subprocess.run(args, capture_output=True, text=True)
    if patchfmt.VERBOSE:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        sys.exit(f"error: command failed ({result.returncode}): {' '.join(str(a) for a in args)}")
    return result.stdout


def addr_comment(addr, raw, decoded):
    return f"# {addr:#x}, {raw.hex()}, {decoded}"


def line_with_comment(content, addr, raw, decoded):
    return f"{content:<40} {addr_comment(addr, raw, decoded)}"


def global_symbol_names(elf):
    names = set()
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return names
    for sym in symtab.iter_symbols():
        if sym["st_info"]["bind"] == "STB_GLOBAL" and sym.name:
            names.add(sym.name)
    return names


def escape_gas_string(data):
    out = []
    for b in data:
        if b in C_ESCAPES:
            out.append(C_ESCAPES[b])
        elif 0x20 <= b < 0x7f:
            out.append(chr(b))
        else:
            out.append("\\%03o" % b)
    return "".join(out)


def is_printable_run(data):
    return all(0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d) for b in data)


def ascii_repr(data):
    return "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data)


def reloc_directive(size):
    return {8: ".quad", 4: ".long", 2: ".word"}.get(size, ".long")


def collect_relocs(elf, section_name):
    result = {}
    for secname in (".rela" + section_name, ".rel" + section_name):
        sec = elf.get_section_by_name(secname)
        if sec is None:
            continue
        symtab = elf.get_section(sec["sh_link"])
        for reloc in sec.iter_relocations():
            sym = symtab.get_symbol(reloc["r_info_sym"])
            sym_name = sym.name
            if not sym_name and sym["st_info"]["type"] == "STT_SECTION":
                target_sec = elf.get_section(sym["st_shndx"])
                sym_name = target_sec.name if target_sec is not None else "?"
            sym_name = sym_name or "?"
            addend = reloc["r_addend"] if reloc.is_RELA() else 0
            rtype = reloc["r_info_type"]
            tname = RELOC_TYPE_NAME_BY_VALUE.get(rtype, str(rtype))
            size = 8 if "64" in tname and "PC" not in tname else 4
            result[reloc["r_offset"]] = (sym_name, addend, size, tname)
    return result


def render_text(objdump_output, globals_seen):
    lines = []
    for raw_line in objdump_output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("Disassembly of section "):
            section = line[len("Disassembly of section "):].rstrip(":")
            lines.append("")
            lines.append(f".section {section}")
            continue
        m = LABEL_RE.match(line)
        if m:
            name = m.group(2)
            if name in globals_seen:
                lines.append(f".global {name}")
            lines.append(f"{name}:")
            continue
        if line.startswith(";"):
            lines.append(f"    # {line[1:].strip()}")
            continue
        m = INSN_RE.match(line)
        if m:
            addr_hex, byte_blob, rest = m.groups()
            rest = rest.strip()
            if not rest:
                continue
            rest = re.sub(r"\s+", " ", rest)
            raw = bytes.fromhex("".join(byte_blob.split()))
            lines.append(line_with_comment(f"    {rest}", int(addr_hex, 16), raw, rest))
            continue
    return lines


DIR_FOR_SIZE = {8: ".quad", 4: ".long", 2: ".word", 1: ".byte"}


def choose_array_unit(size):
    for unit in (8, 4, 2, 1):
        if size % unit == 0 and size >= unit:
            return unit
    return 1


def emit_numeric(lines, data, addr, indent="    "):
    unit = choose_array_unit(len(data))
    directive = DIR_FOR_SIZE[unit]
    per_line = {8: 4, 4: 8, 2: 8, 1: 8}[unit]
    for i in range(0, len(data), unit * per_line):
        chunk = data[i:i + unit * per_line]
        vals = []
        for j in range(0, len(chunk), unit):
            word = chunk[j:j + unit]
            val = int.from_bytes(word, "little")
            vals.append("0x%0*x" % (unit * 2, val))
        decoded = ", ".join(vals)
        lines.append(line_with_comment(f"{indent}{directive} {decoded}", addr + i, chunk, decoded))


def emit_bytes_with_ascii(lines, data, addr, indent="    "):
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        hexpart = ", ".join("0x%02x" % b for b in chunk)
        decoded = f'"{ascii_repr(chunk)}"'
        lines.append(line_with_comment(f"{indent}.byte {hexpart}", addr + i, chunk, decoded))


def render_symbol_body(lines, data, relocs, sym_start):
    n = len(data)
    local_relocs = sorted((off - sym_start, v) for off, v in relocs.items()
                           if sym_start <= off < sym_start + n)
    if not local_relocs:
        if n >= 2 and data[-1] == 0 and data.count(0) == 1 and is_printable_run(data[:-1]):
            s = escape_gas_string(data[:-1])
            lines.append(line_with_comment(f'    .asciz "{s}"', sym_start, data, f'"{s}"'))
        elif n >= 1 and is_printable_run(data) and data[-1] != 0:
            s = escape_gas_string(data)
            lines.append(line_with_comment(f'    .ascii "{s}"', sym_start, data, f'"{s}"'))
        elif n > 0:
            emit_numeric(lines, data, sym_start)
        return

    cursor = 0
    for rel_off, (sym_name, addend, size, tname) in local_relocs:
        if rel_off > cursor:
            gap = data[cursor:rel_off]
            if len(gap) in DIR_FOR_SIZE:
                emit_numeric(lines, gap, sym_start + cursor)
            else:
                emit_bytes_with_ascii(lines, gap, sym_start + cursor)
        directive = reloc_directive(size)
        target = sym_name if addend == 0 else f"{sym_name}{'+' if addend >= 0 else ''}{addend}"
        chunk = data[rel_off:rel_off + size]
        lines.append(line_with_comment(f"    {directive} {target}", sym_start + rel_off, chunk,
                                        f"reloc {tname} -> {target}"))
        cursor = rel_off + size
    if cursor < n:
        tail = data[cursor:]
        if len(tail) in DIR_FOR_SIZE:
            emit_numeric(lines, tail, sym_start + cursor)
        else:
            emit_bytes_with_ascii(lines, tail, sym_start + cursor)


def render_data_sections(elf, want_sections=None):
    lines = []
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return lines

    syms_by_shndx = {}
    for sym in symtab.iter_symbols():
        if sym["st_info"]["type"] not in ("STT_OBJECT", "STT_NOTYPE"):
            continue
        if not sym.name:
            continue
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int):
            continue
        syms_by_shndx.setdefault(shndx, []).append(sym)

    for idx, sec in enumerate(elf.iter_sections()):
        flags = sec["sh_flags"]
        if not (flags & SH_FLAGS.SHF_ALLOC):
            continue
        if flags & SH_FLAGS.SHF_EXECINSTR:
            continue
        if sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
            continue
        name = sec.name
        if want_sections and name not in want_sections:
            continue
        syms = sorted(
            (s for s in syms_by_shndx.get(idx, []) if s["st_size"] > 0 or s["st_value"] > 0),
            key=lambda s: (s["st_value"], -s["st_size"]),
        )
        seen = set()
        dedup = []
        for s in syms:
            key = (s["st_value"], s["st_size"])
            if key in seen:
                continue
            seen.add(key)
            dedup.append(s)
        syms = dedup
        if not syms:
            continue

        is_bss = sec["sh_type"] == "SHT_NOBITS"
        sec_addr = sec["sh_addr"]
        raw = b"" if is_bss else sec.data()
        relocs = {} if is_bss else collect_relocs(elf, name)

        lines.append("")
        lines.append(f".section {name}")
        cursor = sec_addr
        for sym in syms:
            addr = sym["st_value"]
            size = sym["st_size"] or 1
            if addr > cursor:
                gap = addr - cursor
                if is_bss:
                    lines.append(line_with_comment(f"    .zero {gap}", cursor, b"\x00" * gap, "0"))
                else:
                    gap_bytes = raw[cursor - sec_addr: addr - sec_addr]
                    if gap_bytes and any(gap_bytes):
                        emit_bytes_with_ascii(lines, gap_bytes, cursor)
                    else:
                        lines.append(line_with_comment(f"    .zero {gap}", cursor,
                                                         gap_bytes or b"\x00" * gap, "0"))
            bind = sym["st_info"]["bind"]
            if bind == "STB_GLOBAL":
                lines.append(f".global {sym.name}")
            lines.append(f"{sym.name}:")
            if is_bss:
                lines.append(line_with_comment(f"    .zero {size:#x}", addr, b"\x00" * size, "0"))
            else:
                body = raw[addr - sec_addr: addr - sec_addr + size]
                render_symbol_body(lines, body, relocs, addr)
            cursor = addr + size
        sec_end = sec_addr + sec["sh_size"]
        if cursor < sec_end:
            gap = sec_end - cursor
            if is_bss:
                lines.append(line_with_comment(f"    .zero {gap}", cursor, b"\x00" * gap, "0"))
            else:
                tail = raw[cursor - sec_addr:]
                if any(tail):
                    emit_bytes_with_ascii(lines, tail, cursor)
                else:
                    lines.append(line_with_comment(f"    .zero {gap}", cursor,
                                                     tail or b"\x00" * gap, "0"))
    return lines


DW_ATE_BOOLEAN = 2
DW_ATE_FLOAT = 4
DW_ATE_SIGNED = 5
DW_ATE_SIGNED_CHAR = 6
DW_ATE_UNSIGNED = 7
DW_ATE_UNSIGNED_CHAR = 8

AGGREGATE_TAGS = ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type")


def _attr_str(die, name):
    a = die.attributes.get(name)
    if a is None:
        return None
    v = a.value
    return v.decode() if isinstance(v, bytes) else v


def strip_typedefs(die):
    while die is not None and die.tag in (
        "DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"
    ):
        if "DW_AT_type" not in die.attributes:
            return None
        die = die.get_DIE_from_attribute("DW_AT_type")
    return die


def array_count(die):
    for child in die.iter_children():
        if child.tag == "DW_TAG_subrange_type":
            if "DW_AT_count" in child.attributes:
                return child.attributes["DW_AT_count"].value
            if "DW_AT_upper_bound" in child.attributes:
                return child.attributes["DW_AT_upper_bound"].value + 1
    return None


def die_byte_size(die):
    if die is None:
        return 0
    if "DW_AT_byte_size" in die.attributes:
        return die.attributes["DW_AT_byte_size"].value
    if die.tag == "DW_TAG_pointer_type":
        return 8
    if die.tag == "DW_TAG_array_type":
        elem = strip_typedefs(die.get_DIE_from_attribute("DW_AT_type"))
        return die_byte_size(elem) * (array_count(die) or 0)
    return 0


def die_type_name(die):
    if die is None:
        return "void"
    if die.tag == "DW_TAG_pointer_type":
        inner = strip_typedefs(die.get_DIE_from_attribute("DW_AT_type")) if "DW_AT_type" in die.attributes else None
        return die_type_name(inner) + " *"
    if die.tag in AGGREGATE_TAGS:
        kind = "union" if die.tag == "DW_TAG_union_type" else "struct"
        return f"{kind} {_attr_str(die, 'DW_AT_name') or '<anon>'}"
    if die.tag == "DW_TAG_enumeration_type":
        return f"enum {_attr_str(die, 'DW_AT_name') or '<anon>'}"
    if die.tag == "DW_TAG_array_type":
        elem = strip_typedefs(die.get_DIE_from_attribute("DW_AT_type"))
        count = array_count(die)
        return f"{die_type_name(elem)}[{count if count is not None else ''}]"
    return _attr_str(die, "DW_AT_name") or die.tag


def decode_scalar(die, data):
    if die is None or not data:
        return data.hex() if data else ""
    if die.tag == "DW_TAG_pointer_type":
        return f"0x{int.from_bytes(data, 'little'):x}"
    if die.tag == "DW_TAG_enumeration_type":
        val = int.from_bytes(data, "little", signed=False)
        for child in die.iter_children():
            if child.tag == "DW_TAG_enumerator":
                cv = child.attributes.get("DW_AT_const_value")
                if cv is not None and cv.value == val:
                    return f"{_attr_str(child, 'DW_AT_name')} ({val})"
        return str(val)
    enc = die.attributes.get("DW_AT_encoding")
    enc = enc.value if enc is not None else None
    size = len(data)
    if enc == DW_ATE_BOOLEAN:
        return "true" if any(data) else "false"
    if enc == DW_ATE_FLOAT:
        if size == 4:
            return repr(_struct.unpack("<f", data)[0])
        if size == 8:
            return repr(_struct.unpack("<d", data)[0])
        return "0x" + data.hex()
    if enc in (DW_ATE_SIGNED_CHAR, DW_ATE_UNSIGNED_CHAR):
        b = data[0]
        ch = chr(b) if 0x20 <= b < 0x7f else "."
        return f"'{ch}' ({b})"
    if enc == DW_ATE_UNSIGNED:
        return str(int.from_bytes(data, "little", signed=False))
    if enc == DW_ATE_SIGNED:
        return str(int.from_bytes(data, "little", signed=True))
    return "0x" + data.hex()


def flatten_dwarf_fields(type_die, raw, field_off, base_addr, relocs, name_prefix, out, depth=0):
    if depth > 12 or type_die is None:
        return

    if type_die.tag in AGGREGATE_TAGS:
        for member in type_die.iter_children():
            if member.tag != "DW_TAG_member":
                continue
            mname = _attr_str(member, "DW_AT_name") or "<anon>"
            loc = member.attributes.get("DW_AT_data_member_location")
            moff = loc.value if (loc is not None and isinstance(loc.value, int)) else 0
            if "DW_AT_type" not in member.attributes:
                continue
            mtype = strip_typedefs(member.get_DIE_from_attribute("DW_AT_type"))
            flatten_dwarf_fields(mtype, raw, field_off + moff, base_addr, relocs,
                                  f"{name_prefix}.{mname}", out, depth + 1)
        return

    if type_die.tag == "DW_TAG_array_type":
        elem = strip_typedefs(type_die.get_DIE_from_attribute("DW_AT_type"))
        elem_size = die_byte_size(elem)
        count = array_count(type_die) or 0
        if elem is not None and elem.tag in AGGREGATE_TAGS and elem_size:
            for i in range(count):
                flatten_dwarf_fields(elem, raw, field_off + i * elem_size, base_addr, relocs,
                                      f"{name_prefix}[{i}]", out, depth + 1)
        else:
            size = elem_size * count
            out.append({
                "name": name_prefix, "type": die_type_name(type_die),
                "offset": field_off, "addr": base_addr + field_off, "size": size,
                "value": f"[{count} x {die_type_name(elem)}]" if count else "[]",
                "raw": raw[field_off:field_off + size],
            })
        return

    size = die_byte_size(type_die)
    data = raw[field_off:field_off + size]
    value = decode_scalar(type_die, data)
    if type_die.tag == "DW_TAG_pointer_type":
        r = relocs.get(base_addr + field_off)
        if r:
            sym_name, addend, _rsize, _tname = r
            value = sym_name if addend == 0 else f"{sym_name}{'+' if addend >= 0 else ''}{addend}"
    out.append({
        "name": name_prefix, "type": die_type_name(type_die),
        "offset": field_off, "addr": base_addr + field_off, "size": size, "value": value,
        "raw": data,
    })


def dwarf_global_var_types(elf):
    try:
        dwarf = elf.get_dwarf_info()
    except Exception:
        return {}
    result = {}
    try:
        for CU in dwarf.iter_CUs():
            top = CU.get_top_DIE()
            for die in top.iter_children():
                if die.tag != "DW_TAG_variable":
                    continue
                ext = die.attributes.get("DW_AT_external")
                if ext is None or ext.value != 1:
                    continue
                name = _attr_str(die, "DW_AT_name")
                if not name or "DW_AT_type" not in die.attributes:
                    continue
                result[name] = strip_typedefs(die.get_DIE_from_attribute("DW_AT_type"))
    except Exception:
        pass
    return result


def is_struct_like(sym, data):
    if sym["st_info"]["bind"] != "STB_GLOBAL" or sym["st_info"]["type"] != "STT_OBJECT":
        return False
    size = sym["st_size"]
    if size == 0 or size in DIR_FOR_SIZE:
        return False
    stripped = data[:-1] if (data and data[-1] == 0) else data
    if stripped and is_printable_run(stripped):
        return False
    return True


def find_global_structs(elf):
    lines = []
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return lines

    dwarf_vars = dwarf_global_var_types(elf)

    syms_by_shndx = {}
    for sym in symtab.iter_symbols():
        if not sym.name:
            continue
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int):
            continue
        syms_by_shndx.setdefault(shndx, []).append(sym)

    dwarf_hits = []
    heuristic_hits = []

    for idx, sec in enumerate(elf.iter_sections()):
        flags = sec["sh_flags"]
        if not (flags & SH_FLAGS.SHF_ALLOC) or (flags & SH_FLAGS.SHF_EXECINSTR):
            continue
        if sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
            continue
        is_bss = sec["sh_type"] == "SHT_NOBITS"
        sec_addr = sec["sh_addr"]
        raw = b"" if is_bss else sec.data()
        relocs = {} if is_bss else collect_relocs(elf, sec.name)

        for sym in syms_by_shndx.get(idx, []):
            addr, size = sym["st_value"], sym["st_size"]
            if size == 0:
                continue
            body = b"\x00" * size if is_bss else raw[addr - sec_addr: addr - sec_addr + size]

            type_die = dwarf_vars.get(sym.name)
            is_aggregate = type_die is not None and (
                type_die.tag in AGGREGATE_TAGS
                or (type_die.tag == "DW_TAG_array_type"
                    and (elem := strip_typedefs(type_die.get_DIE_from_attribute("DW_AT_type"))) is not None
                    and elem.tag in AGGREGATE_TAGS)
            )
            if is_aggregate:
                dwarf_hits.append((sym.name, sec.name, addr, size, type_die, body, relocs))
            elif type_die is None and is_struct_like(sym, body):
                heuristic_hits.append((sym.name, sec.name, addr, size, body, relocs, is_bss))

    if not dwarf_hits and not heuristic_hits:
        return lines

    lines.append("")
    lines.append("# ---- global struct data ----")

    if dwarf_hits:
        dwarf_hits.sort(key=lambda t: (t[1], t[2]))
        lines.append("# from DWARF debug info: member name, type, offset, address, decoded value")
        for name, secname, addr, size, type_die, body, relocs in dwarf_hits:
            lines.append(f"{name}: {die_type_name(type_die)}  # section={secname} addr=0x{addr:x} size=0x{size:x}")
            fields = []
            if type_die.tag == "DW_TAG_array_type":
                elem = strip_typedefs(type_die.get_DIE_from_attribute("DW_AT_type"))
                elem_size = die_byte_size(elem)
                for i in range(array_count(type_die) or 0):
                    flatten_dwarf_fields(elem, body, i * elem_size, addr, relocs, f"[{i}]", fields)
            else:
                flatten_dwarf_fields(type_die, body, 0, addr, relocs, "", fields)
            for f in fields:
                fname = f["name"][1:] if f["name"].startswith(".") else f["name"]
                content = f"    {fname:<24} {f['type']:<16} off=0x{f['offset']:x}"
                lines.append(line_with_comment(content, f["addr"], f.get("raw", b""), str(f["value"])))

    if heuristic_hits:
        heuristic_hits.sort(key=lambda t: (t[1], t[2]))
        lines.append("# no DWARF match (no debug info / stripped) -- raw byte-pattern guess:")
        for name, secname, addr, size, body, relocs, is_bss in heuristic_hits:
            lines.append(f"{name}: # section={secname} addr=0x{addr:x} size=0x{size:x}")
            if is_bss:
                lines.append(line_with_comment("    .zero 0x{:x}".format(size), addr, b"\x00" * size, "0"))
            else:
                render_symbol_body(lines, body, relocs, addr)
    return lines


def parse_instructions(objdump_output):
    rows = []
    section = None
    label = None
    for raw in objdump_output.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("Disassembly of section "):
            section = line[len("Disassembly of section "):].rstrip(":")
            continue
        m = LABEL_RE.match(line.strip())
        if m:
            label = m.group(2)
            continue
        m = INSN_RE.match(line)
        if m:
            addr, byte_blob, text = m.groups()
            byte_str = " ".join(byte_blob.split())
            text = re.sub(r"\s+", " ", text.strip())
            if text:
                rows.append((section, label, int(addr, 16), byte_str, text))
    return rows


def dump_data_symbol(sym, sec, relocs, bytes_per_line):
    sec_addr = sec["sh_addr"]
    is_bss = sec["sh_type"] == "SHT_NOBITS"
    addr, size = sym["st_value"], sym["st_size"] or 1

    if is_bss:
        yield (addr, "", f"<{sym.name}> .zero 0x{size:x}  (bss, uninitialized)")
        return

    raw = sec.data()
    body = raw[addr - sec_addr: addr - sec_addr + size]

    stripped = body[:-1] if (body and body[-1] == 0) else body
    if stripped and is_printable_run(stripped):
        yield (addr, " ".join(f"{b:02x}" for b in body), f'<{sym.name}> "{ascii_repr(stripped)}"')
        return

    for off in range(0, len(body), bytes_per_line):
        chunk = body[off:off + bytes_per_line]
        chunk_addr = addr + off
        r = relocs.get(chunk_addr)
        byte_str = " ".join(f"{b:02x}" for b in chunk)
        if r:
            rsym, addend, _size, _tname = r
            target = rsym if addend == 0 else f"{rsym}{'+' if addend >= 0 else ''}{addend}"
            text = f"<{sym.name}+0x{off:x}> reloc -> {target}"
        else:
            text = f"<{sym.name}+0x{off:x}> {ascii_repr(chunk)}"
        yield (chunk_addr, byte_str, text)


def parse_data(elf, want_section, bytes_per_line):
    rows = []
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return rows

    syms_by_shndx = {}
    for sym in symtab.iter_symbols():
        if not sym.name:
            continue
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int):
            continue
        syms_by_shndx.setdefault(shndx, []).append(sym)

    for idx, sec in enumerate(elf.iter_sections()):
        flags = sec["sh_flags"]
        if not (flags & SH_FLAGS.SHF_ALLOC) or (flags & SH_FLAGS.SHF_EXECINSTR):
            continue
        if sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
            continue
        if want_section and sec.name != want_section:
            continue
        relocs = {} if sec["sh_type"] == "SHT_NOBITS" else collect_relocs(elf, sec.name)
        syms = sorted(
            (s for s in syms_by_shndx.get(idx, []) if s["st_size"] > 0),
            key=lambda s: s["st_value"],
        )
        for sym in syms:
            for addr, byte_str, text in dump_data_symbol(sym, sec, relocs, bytes_per_line):
                rows.append((sec.name, addr, byte_str, text))
    return rows


def run_rows_mode(args):
    combined = []

    if not args.data_only:
        objdump_out = run_objdump(
            args.elf, args.objdump, args.section,
            "att" if args.att else "intel", not args.no_symbolize, False,
        )
        for section, label, addr, byte_str, text in parse_instructions(objdump_out):
            combined.append(("insn", section, label, addr, byte_str, text))

    if not args.text_only:
        with open(args.elf, "rb") as f:
            elf = ELFFile(f)
            for section, addr, byte_str, text in parse_data(elf, args.section, args.bytes_per_line):
                combined.append(("data", section, None, addr, byte_str, text))

    if not combined:
        sys.exit("nothing found -- wrong --section name, or an empty/unsupported input?")

    sep = "," if args.csv else "\t"
    lines = []
    last_section = None
    last_label = None
    for kind, section, label, addr, byte_str, text in combined:
        if section != last_section:
            lines.append(f"# section {section}")
            last_section = section
            last_label = None
        if kind == "insn" and args.with_labels and label != last_label:
            lines.append(f"# {label}:")
            last_label = label
        lines.append(sep.join([f"0x{addr:x}", byte_str, text]))

    output_text = "\n".join(lines) + "\n"
    if args.output:
        patchfmt.ensure_parent(args.output)
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"wrote {args.output} ({len(combined)} rows)")
    else:
        sys.stdout.write(output_text)


def run_pretty_mode(args):
    with open(args.elf, "rb") as f:
        elf = ELFFile(f)
        globals_seen = global_symbol_names(elf)
        data_lines = [] if args.text_only else render_data_sections(elf)
        struct_lines = [] if (args.text_only or args.no_struct_summary) else find_global_structs(elf)

    text_lines = []
    if not args.data_only:
        objdump_out = run_objdump(
            args.elf, args.objdump, args.section,
            "att" if args.att else "intel", not args.no_symbolize, not args.no_source,
        )
        text_lines = render_text(objdump_out, globals_seen)

    if not args.output:
        sys.exit("error: --mode pretty requires -o/--output")

    patchfmt.ensure_parent(args.output)
    with open(args.output, "w") as f:
        f.write(f"# generated by dump.py from {args.elf}\n")
        f.write(".intel_syntax noprefix\n")
        for line in text_lines:
            f.write(line + "\n")
        for line in data_lines:
            f.write(line + "\n")
        for line in struct_lines:
            f.write(line + "\n")

    print(f"wrote {args.output}")

