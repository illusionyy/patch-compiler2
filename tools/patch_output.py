#!/usr/bin/env python3
import json
import sys
from pathlib import Path

import patchfmt


def option_friendly(opt):
    return opt.get("friendly") or f"{opt['struct']}.{opt['member']}"


def option_value_hex(opt):
    return opt["value"].to_bytes(opt["size"], "little").hex()


def lines_from_chunks(chunks):
    return [{"address": c["addr"], "value": c["bytes"], "label": c["label"]} for c in chunks]


def check_overlap(chunks, allow_overlap, context):
    overlaps = patchfmt.find_overlaps(chunks)
    if overlaps and not allow_overlap:
        for a, b in overlaps:
            print(f"error: overlap in {context}: [{a['label']}] 0x{a['addr']:x}..0x{patchfmt.chunk_end(a):x} "
                  f"vs [{b['label']}] 0x{b['addr']:x}..0x{patchfmt.chunk_end(b):x}", file=sys.stderr)
        sys.exit(f"error: {len(overlaps)} overlapping chunk(s) in {context}, use --allow-overlap to force")


def build_entries(code_chunks, packages, allow_overlap, meta):
    entries = []

    if packages:
        for pkg in packages:
            option_addrs = {opt["addr"] for opt in pkg.get("options", [])}
            non_option_chunks = [c for c in pkg.get("chunks", []) if c["addr"] not in option_addrs]
            main_chunks = code_chunks if pkg.get("has_main") else []
            merged = patchfmt.merge(main_chunks, non_option_chunks)
            check_overlap(merged, allow_overlap, f"package '{pkg.get('title', meta['title'])}'")
            entries.append(pkg_entry(pkg, meta, lines_from_chunks(merged)))

        for pkg in packages:
            for opt in pkg.get("options", []):
                friendly = option_friendly(opt)
                entries.append(pkg_entry(pkg, meta, [{
                    "address": opt["addr"],
                    "value": option_value_hex(opt),
                    "label": friendly,
                }], title_override=friendly))
    else:
        check_overlap(code_chunks, allow_overlap, "merged chunk_files")
        entries.append({**meta, "lines": lines_from_chunks(code_chunks)})

    return entries


def pkg_entry(pkg, meta, lines, title_override=None):
    entry = {key: pkg.get(key, meta[key]) for key in ("title", "note", "author", "version",
                                                        "name", "app_elf")}
    if title_override is not None:
        entry["title"] = title_override
    entry["title_id"] = pkg.get("title_id") or meta["title_id"]
    entry["app_ver"] = pkg.get("app_ver") or meta["app_ver"]
    entry["lines"] = lines
    return entry


def emit_json(entries, path):
    patchfmt.ensure_parent(path)
    Path(path).write_text(json.dumps(entries, indent=2) + "\n")

