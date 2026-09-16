#!/usr/bin/env python3
from patchtext import PatchTextFormatter


class XboxPyFormatter(PatchTextFormatter):
    ext = "py"

    @staticmethod
    def _pystr(s):
        return repr(s or "")

    def header(self, entries):
        return "lines_by_patch = {"

    def footer(self, entries):
        return "}"

    def entry_open(self, entry):
        return f"{self._pystr(entry['title'])}: ["

    def entry_close(self, entry):
        return "],"

    def format_line(self, line):
        addr = f'0x{line["address"]:08x}'
        comment = f"  # {line['label']}" if self.comments and line.get("label") else ""
        return f'    {{"addr": {addr}, "data": bytes.fromhex({self._pystr(line["value"])})}},{comment}'


FORMATTERS = {
    "xbox-py": XboxPyFormatter,
}

