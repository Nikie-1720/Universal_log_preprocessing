"""Generic key=value parser (logfmt / FortiGate / MicroFocus style)."""
from __future__ import annotations

import re

from ulpf.parsers.base import ParseResult, Parser
from ulpf.taxonomy import INFERENCE_BY_KEY
from ulpf.utils import parse_timestamp

DEFAULT_PAIR = re.compile(r"(?<![\w])([A-Za-z_][\w.\-]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,;]+))")


class KVParser(Parser):
    id = "kv"
    format_name = "kv"
    priority = 30

    def _pattern(self):
        pat = self.options.get("pattern")
        if pat:
            return re.compile(pat)
        return DEFAULT_PAIR

    def match(self, raw: str) -> float:
        pairs = self._pattern().findall(raw)
        if len(pairs) >= 2:
            return min(0.9, 0.5 + len(pairs) * 0.05)
        return 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        attrs = {}
        for m in self._pattern().finditer(raw):
            key = m.group(1)
            value = next((g for g in m.groups()[1:] if g is not None), "")
            attrs[key] = value
        if not attrs:
            result.warnings.append("no key=value pairs found")
            return result
        result.attributes = attrs
        low = {k.lower(): v for k, v in attrs.items()}
        for key, (target, ctype) in INFERENCE_BY_KEY.items():
            if target == "message" and key in low and isinstance(low[key], str):
                result.message = low[key]
            elif target == "event_time" and key in low:
                result.event_time = parse_timestamp(low[key]) or low[key]
        return result
