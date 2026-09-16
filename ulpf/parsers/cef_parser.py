"""ArcSight Common Event Format (CEF) parser."""
from __future__ import annotations

import re

from ulpf.parsers.base import ParseResult, Parser

RE_CEF = re.compile(
    r"^CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dver>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|?(?P<ext>.*)$", re.S)
RE_KEY_POS = re.compile(r"(?:^|\s)([\w.]+)=")


def _unescape(value: str) -> str:
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "r": "\r", "=": "=", "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _parse_extension(ext: str) -> dict:
    """Split a CEF extension string into key/value pairs (spaces inside values kept)."""
    attrs = {}
    keys = [(m.group(1), m.end()) for m in RE_KEY_POS.finditer(" " + ext)]
    keys = [(k, p - 1) for k, p in keys]  # compensate for the leading space
    for idx, (key, start) in enumerate(keys):
        end = keys[idx + 1][1] - len(keys[idx + 1][0]) - 1 if idx + 1 < len(keys) else len(ext)
        value = ext[start:end].strip()
        attrs[key] = _unescape(value)
    return attrs


class CEFParser(Parser):
    id = "cef"
    format_name = "cef"
    priority = 20

    def match(self, raw: str) -> float:
        return 0.98 if RE_CEF.match(raw.strip()) else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        m = RE_CEF.match(raw.strip())
        if not m:
            result.warnings.append("CEF header not found")
            return result
        g = m.groupdict()
        ext = _parse_extension(g["ext"] or "")
        result.attributes = {
            "cef.version": g["ver"],
            "device.vendor": g["vendor"],
            "device.product": g["product"],
            "device.version": g["dver"],
            "cef.signature_id": g["sig"],
            "cef.name": g["name"],
            **ext,
        }
        result.hints = {
            "vendor": g["vendor"],
            "product": g["product"],
            "severity_raw": g["sev"],
        }
        result.message = ext.get("msg") or g["name"]
        result.event_time = ext.get("rt") or ext.get("start") or None
        return result
