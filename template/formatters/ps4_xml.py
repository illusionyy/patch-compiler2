#!/usr/bin/env python3
from patchtext import PatchTextFormatter


class Ps4XmlFormatter(PatchTextFormatter):
    ext = "xml"

    def header(self, entries):
        from xml.sax.saxutils import escape

        title_ids = []
        for entry in entries:
            for tid in entry.get("title_id") or []:
                if tid not in title_ids:
                    title_ids.append(tid)

        lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Patch>", "    <TitleID>"]
        for tid in title_ids:
            lines.append(f"        <ID>{escape(tid)}</ID>")
        lines.append("    </TitleID>")
        return "\n".join(lines)

    def footer(self, entries):
        return "</Patch>"

    def entry_open(self, entry):
        from xml.sax.saxutils import quoteattr

        app_ver = ",".join(entry.get("app_ver") or [])
        return (
            f'    <Metadata Title={quoteattr(entry["title"])}\n'
            f'              Name={quoteattr(entry.get("name") or "")}\n'
            f'              Note={quoteattr(entry.get("note") or "")}\n'
            f'              Author={quoteattr(entry.get("author") or "")}\n'
            f'              PatchVer={quoteattr(entry.get("version") or "")}\n'
            f'              AppVer={quoteattr(app_ver)}\n'
            f'              AppElf={quoteattr(entry.get("app_elf") or "")}>\n'
            f'        <PatchList>'
        )

    def entry_close(self, entry):
        return "        </PatchList>\n    </Metadata>"

    def format_line(self, line):
        from xml.sax.saxutils import escape

        parts = []
        if self.comments and line.get("label"):
            parts.append(f'            <!-- {escape(line["label"])} -->')
        addr = f'0x{line["address"]:08x}'
        parts.append(f'            <Line Type="bytes" Address="{addr}" Value="{line["value"]}"/>')
        return "\n".join(parts)


FORMATTERS = {
    "ps4-xml": Ps4XmlFormatter,
}

