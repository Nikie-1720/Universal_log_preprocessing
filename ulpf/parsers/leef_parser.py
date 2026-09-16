"""Log Event Extended Format (LEEF) parser (LEEF 1.x/2.x, incl. sep= delimiters)."""
from __future__ import annotations

import re

from ulpf.parsers.base import ParseResult, Parser

RE_LEEF = re.compile(
    r"^LEEF:(?P<ver>\d+\.\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<pver>[^|]*)\|"
    r"(?P<eid>[^|]*)\|(?P<rest>.*)$", re.S)
RE_SEP = re.compile(r"^sep=(0x[0-9a-fA-F]{1,2}|\S)\|")
RE_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _resolve_sep(rest: str):
    m = RE_SEP.match(rest)
    if not m:
        return "\t", rest
    spec = m.group(1)
    payload = rest[m.end():]
    if spec.lower().startswith("0x"):
        sep = chr(int(spec, 16))
    else:
        sep = spec
    return sep, payload


class LEEFParser(Parser):
    id = "leef"
    format_name = "leef"
    priority = 20

    def match(self, raw: str) -> float:
        return 0.98 if RE_LEEF.match(raw.strip()) else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        m = RE_LEEF.match(raw.strip())
        if not m:
            result.warnings.append("LEEF header not found")
            return result
        g = m.groupdict()
        sep, payload = _resolve_sep(g["rest"])
        # Some producers emit textual \xHH escapes instead of raw control chars
        if sep not in payload and RE_HEX_ESCAPE.search(payload):
            payload = RE_HEX_ESCAPE.sub(lambda hm: chr(int(hm.group(1), 16)), payload)
        attrs = {
            "leef.version": g["ver"],
            "device.vendor": g["vendor"],
            "device.product": g["product"],
            "leef.product_version": g["pver"],
            "leef.event_id": g["eid"],
        }
        for pair in payload.split(sep):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
                attrs[k.strip()] = v.strip()
        result.attributes = attrs
        result.hints = {"vendor": g["vendor"], "product": g["product"],
                        "severity_raw": attrs.get("sev")}
        result.message = attrs.get("msg") or attrs.get("name") or g["eid"]
        result.event_time = attrs.get("devTime")
        return result
