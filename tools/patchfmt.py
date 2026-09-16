#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
import re

VERBOSE = False


def set_verbose(v: bool):
    global VERBOSE
    VERBOSE = v


def vprint(*a, **kw):
    if VERBOSE:
        print(*a, **kw)


def run(cmd, log_path=None, **kw):
    printable = " ".join(str(c) for c in cmd)
    print("+", printable + (f"  > {log_path}" if log_path else ""), file=sys.stderr)
    result = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    if log_path:
        Path(log_path).write_text(result.stdout + result.stderr)
    if VERBOSE or result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        sys.exit(f"error: command failed ({result.returncode}): {printable}")
    return result


def make_chunk(addr, data: bytes, label=""):
    return {"addr": addr, "bytes": data.hex(), "label": label}


def chunk_bytes(chunk):
    return bytes.fromhex(chunk["bytes"])


def chunk_end(chunk):
    return chunk["addr"] + len(chunk_bytes(chunk))


def ensure_parent(path):
    parent = Path(path).parent
    if parent:
        parent.mkdir(parents=True, exist_ok=True)


def load(path):
    return json.loads(Path(path).read_text())


def save(path, chunks):
    ensure_parent(path)
    chunks = sorted(chunks, key=lambda c: c["addr"])
    Path(path).write_text(json.dumps(chunks, indent=2) + "\n")


def merge(*chunk_lists):
    merged = []
    for lst in chunk_lists:
        merged.extend(lst)
    return sorted(merged, key=lambda c: c["addr"])


SYNTAX_RE = re.compile(r'^\s*\.(att|intel)_syntax\b')


def default_syntax_preamble(lines):
    for raw in lines:
        code = raw.split("#", 1)[0].split(";", 1)[0]
        if SYNTAX_RE.match(code):
            return []
    return [".intel_syntax noprefix"]


LITERAL_JUMP_RE = re.compile(
    r'^(\s*(?:jmp|call)\s+)(0[xX][0-9a-fA-F]+|\d+)(\s*(?:[#;].*)?)$')


def dodge_literal_jump_targets(lines):
    new_lines = []
    literal_syms = {}
    for raw in lines:
        m = LITERAL_JUMP_RE.match(raw)
        if m:
            value = int(m.group(2), 0)
            name = f"__lit_{value:x}"
            literal_syms[name] = value
            new_lines.append(f"{m.group(1)}{name}{m.group(3)}")
        else:
            new_lines.append(raw)
    return new_lines, literal_syms


LABEL_RE = re.compile(r'^\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*:')


def block_labels(lines):
    names = []
    for raw in lines:
        line = raw.split("#", 1)[0].split(";", 1)[0]
        m = LABEL_RE.match(line)
        if m:
            name = m.group(1)
            if name[0] != "." and not name[0].isdigit():
                names.append(name)
    return names


def find_overlaps(chunks):
    chunks = sorted(chunks, key=lambda c: c["addr"])
    overlaps = []
    for a, b in zip(chunks, chunks[1:]):
        if chunk_end(a) > b["addr"]:
            overlaps.append((a, b))
    return overlaps


def coalesce(chunks):
    chunks = sorted(chunks, key=lambda c: c["addr"])
    out = []
    for c in chunks:
        if out and chunk_end(out[-1]) == c["addr"] and out[-1]["label"] == c["label"]:
            out[-1] = make_chunk(out[-1]["addr"], chunk_bytes(out[-1]) + chunk_bytes(c), c["label"])
        else:
            out.append(dict(c))
    return out

