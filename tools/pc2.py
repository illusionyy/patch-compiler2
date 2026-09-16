#!/usr/bin/env python3
import argparse
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asm_syms
import build_patch
import extract_patch_bytes
import patch_asm
import patch_output
import patchfmt
import patchtext
import symres


def parse_hex(s):
    return int(s, 16) if s else None


def load_format_script(path, formatters):
    spec = importlib.util.spec_from_file_location(Path(path).stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    extra = getattr(mod, "FORMATTERS", None)
    if not extra:
        sys.exit(f"error: --format-script {path} defines no FORMATTERS dict")
    formatters.update(extra)


def compute_asm_defsyms(patch_asm_files, workdir: Path):
    all_syms = {}
    overall_next_free = None
    section_bases = {}
    for src in patch_asm_files:
        if not Path(src).exists():
            sys.exit(f"error: source file not found: {src}")
        packages = patch_asm.parse_packages(src)
        for pkg in packages:
            for key in ("rodata_base", "data_base"):
                value = pkg.get(key)
                if value is None:
                    continue
                if key in section_bases and section_bases[key] != value:
                    sys.exit(f"error: {key} defined at two different addresses "
                              f"across --patch-asm input files")
                section_bases[key] = value
        blocks = asm_syms.literal_blocks(packages)
        syms, next_free = asm_syms.label_addresses(blocks, workdir / "asm_syms", Path(src).stem)
        for name, addr in syms.items():
            if name in all_syms and all_syms[name] != addr:
                sys.exit(f"error: label '{name}' defined at two different addresses "
                          f"across --patch-asm input files")
            all_syms[name] = addr
        if next_free is not None:
            overall_next_free = next_free if overall_next_free is None else max(overall_next_free, next_free)
    return all_syms, overall_next_free, section_bases


def compile_and_link(sources, workdir: Path, target, text_base, rodata_base, data_base,
                      base, defsyms):
    if target == "pe32":
        objs = build_patch.compile_sources_pe32(sources, workdir)
        merged, _merged_map = build_patch.link_pe32(objs, workdir, base, defsyms)
        return merged, merged

    objs = build_patch.compile_sources(sources, workdir)
    merged = build_patch.link(objs, workdir, text_base, rodata_base, data_base, base, defsyms)
    return merged, merged


def run_patch_asm(patch_asm_files, syms_obj, workdir: Path, target):
    table = symres.SymbolTable([str(syms_obj)])
    patchfmt.vprint(f"resolved {len(table.syms)} global symbol(s) from {syms_obj}")

    backend = patch_asm.assemble_and_link_pe32 if target == "pe32" else patch_asm.assemble_and_link
    all_chunks = []
    all_packages = []
    main_owner = None

    for src in patch_asm_files:
        if not Path(src).exists():
            sys.exit(f"error: source file not found: {src}")
        file_tag = Path(src).stem
        for pkg in patch_asm.parse_packages(src):
            resolved_blocks = []
            for blk in pkg["blocks"]:
                addr, info = table.resolve(blk["addr"])
                resolved_blocks.append({"addr": addr, "lines": blk["lines"],
                                         "info": info, "friendly": blk["friendly"]})
            patch_asm.check_block_overlap(resolved_blocks)

            if pkg["legacy"]:
                out_tag, label = file_tag, f"asm:{file_tag}"
            else:
                pkg_tag = patch_asm.slugify(pkg["title"] if pkg["title"] else str(pkg["index"]))
                out_tag = f"{file_tag}_{pkg_tag}"
                label = f"asm:{file_tag}:{pkg['title'] if pkg['title'] else pkg['index']}"

            if pkg["has_main"]:
                if main_owner is not None:
                    sys.exit(f"error: .main declared in more than one package across "
                              f"--patch-asm inputs ({main_owner} and {label})")
                main_owner = label

            chunks, options = backend(resolved_blocks, pkg["preamble"], table.syms,
                                       workdir, out_tag, label)
            all_chunks.extend(chunks)
            all_packages.append({
                "title": pkg["title"], "note": pkg["note"], "author": pkg["author"],
                "version": pkg["version"], "name": pkg["name"], "app_ver": pkg["app_ver"],
                "app_elf": pkg["app_elf"], "title_id": pkg["title_id"], "has_main": pkg["has_main"],
                "chunks": chunks, "options": options,
            })

    return all_chunks, all_packages

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+")
    ap.add_argument("--patch-asm", nargs="*", default=[])
    ap.add_argument("--outdir", default="build")
    ap.add_argument("--target", choices=["elf64", "pe32"], default="elf64")

    ap.add_argument("--text", dest="text_base")
    ap.add_argument("--rodata", dest="rodata_base")
    ap.add_argument("--data", dest="data_base")
    ap.add_argument("--base", dest="base")

    ap.add_argument("--output-symbol", default="patch_chunks")
    ap.add_argument("--packages", action="store_true")
    ap.add_argument("--allow-overlap", action="store_true")

    ap.add_argument("--format")
    ap.add_argument("--format-script")

    ap.add_argument("--title", default="patch")
    ap.add_argument("--note", default="")
    ap.add_argument("--author", default="")
    ap.add_argument("--version", default="")
    ap.add_argument("--name", default="")
    ap.add_argument("--app-ver", action="append", default=[])
    ap.add_argument("--app-elf", default="")
    ap.add_argument("--title-id", action="append", default=[])

    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    patchfmt.set_verbose(args.verbose)

    outdir = Path(args.outdir)
    workdir = outdir / "work"
    outdir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)

    if args.target == "pe32":
        blocked = [n for n, v in (("--text", args.text_base), ("--rodata", args.rodata_base),
                                   ("--data", args.data_base)) if v is not None]
        if blocked:
            sys.exit(f"error: {', '.join(blocked)} not supported with --target pe32 (use --base)")

    formatters = dict(patchtext.FORMATTERS)
    if args.format_script:
        load_format_script(args.format_script, formatters)
    if args.format and args.format not in formatters:
        sys.exit(f"error: unknown --format {args.format!r} (known: {', '.join(formatters)}) "
                  f"- pass --format-script to register a project-specific one")

    defsyms, asm_next_free, asm_section_bases = (
        compute_asm_defsyms(args.patch_asm, workdir) if args.patch_asm else ({}, None, {}))

    if args.target == "pe32" and asm_section_bases:
        sys.exit("error: .patch_rodata_base/.patch_data_base not supported with "
                  "--target pe32 (use --base)")

    if args.base == "auto":
        if asm_next_free is None:
            sys.exit("error: --base auto requires --patch-asm with at least one labeled "
                      "literal .addr block")
        base = asm_next_free
    else:
        base = parse_hex(args.base)

    rodata_base = parse_hex(args.rodata_base) if args.rodata_base else asm_section_bases.get("rodata_base")
    data_base = parse_hex(args.data_base) if args.data_base else asm_section_bases.get("data_base")

    final_obj, syms_obj = compile_and_link(
        args.sources, workdir, args.target,
        parse_hex(args.text_base), rodata_base, data_base,
        base, defsyms,
    )

    if args.target == "pe32":
        compiled_chunks = extract_patch_bytes.extract_pe32_split(final_obj, args.objdump)
    else:
        compiled_chunks = extract_patch_bytes.extract_split(final_obj, args.objdump)
    if not compiled_chunks:
        sys.exit(f"error: no allocated .text/.rodata/.data content found in {final_obj}")
    patchfmt.save(workdir / "compiled.chunks.json", compiled_chunks)

    hotpatch_chunks, packages = [], []
    if args.patch_asm:
        hotpatch_chunks, packages = run_patch_asm(args.patch_asm, syms_obj, workdir, args.target)
        patchfmt.save(workdir / "hotpatch.chunks.json", hotpatch_chunks)

    if args.packages and packages:
        code_chunks = compiled_chunks
    else:
        code_chunks = patchfmt.merge(compiled_chunks, hotpatch_chunks) if hotpatch_chunks else compiled_chunks

    meta = {"title": args.title, "note": args.note, "author": args.author, "version": args.version,
            "name": args.name, "app_ver": args.app_ver, "app_elf": args.app_elf,
            "title_id": args.title_id}
    entries = patch_output.build_entries(code_chunks, packages if args.packages else [],
                                          args.allow_overlap, meta)

    if args.format:
        cls = formatters[args.format]
        final_out = outdir / f"final.{cls.ext}"
        release_out = outdir / f"release.{cls.ext}"
        cls(comments=False).write(entries, final_out)
        cls(comments=True).write(entries, release_out)
        print(f"wrote {final_out} and {release_out}")

if __name__ == "__main__":
    main()

