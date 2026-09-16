#!/usr/bin/env python3
from pathlib import Path

import patchfmt


class PatchTextFormatter:
    ext = "txt"

    def __init__(self, comments=True):
        self.comments = comments

    def header(self, entries):
        return None

    def footer(self, entries):
        return None

    def entry_open(self, entry):
        fields = ("title", "note", "author", "version", "name", "app_elf")
        parts = [f"{key}: {entry[key]}" for key in fields if entry.get(key)]
        if entry.get("title_id"):
            parts.append("title_id: " + ", ".join(entry["title_id"]))
        if entry.get("app_ver"):
            parts.append("app_ver: " + ", ".join(entry["app_ver"]))
        return "\n".join(parts)

    def entry_close(self, entry):
        return None

    def format_line(self, line):
        label = f"  ; {line['label']}" if self.comments and line.get("label") else ""
        return f"  0x{line['address']:08x}  {line['value']}{label}"

    def render(self, entries):
        parts = []

        head = self.header(entries)
        if head is not None:
            parts.append(head)

        for entry in entries:
            open_ = self.entry_open(entry)
            if open_ is not None:
                parts.append(open_)
            for line in entry["lines"]:
                parts.append(self.format_line(line))
            close = self.entry_close(entry)
            if close is not None:
                parts.append(close)

        foot = self.footer(entries)
        if foot is not None:
            parts.append(foot)

        return "\n".join(parts) + "\n"

    def write(self, entries, path):
        patchfmt.ensure_parent(path)
        Path(path).write_text(self.render(entries))


FORMATTERS = {
    "txt": PatchTextFormatter,
}

