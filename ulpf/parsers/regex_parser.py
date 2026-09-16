"""Config-driven regex parser (named-group patterns for YAML-defined sources)."""
from __future__ import annotations

import re

from ulpf.parsers.base import ParseResult, Parser
from ulpf.utils import parse_timestamp

TIME_GROUP_NAMES = ("time", "ts", "date", "timestamp", "datetime", "clock")


class RegexParser(Parser):
    id = "regex"
    format_name = "regex"
    priority = 40

    def _patterns(self):
        pats = self.options.get("patterns") or []
        single = self.options.get("pattern")
        if single:
            pats = [single, *pats]
        flags = re.I if self.options.get("case_insensitive") else 0
        return [re.compile(p, flags) for p in pats]

    def match(self, raw: str) -> float:
        if not self._patterns():
            return 0.0
        return 0.8 if any(p.search(raw) for p in self._patterns()) else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        for pattern in self._patterns():
            m = pattern.search(raw)
            if not m:
                continue
            groups = {k: v for k, v in m.groupdict().items() if v is not None}
            result.attributes = groups
            if groups.get("pri"):
                try:
                    result.pri = int(str(groups["pri"]).strip("<>"))
                except ValueError:
                    pass
            result.message = groups.get("msg") or groups.get("message") or raw.strip()[:400]
            for name in TIME_GROUP_NAMES:
                if name in groups:
                    fmt = self.options.get("time_format")
                    result.event_time = parse_timestamp(groups[name]) if not fmt else None
                    if fmt:
                        from datetime import datetime
                        try:
                            dt = datetime.strptime(groups[name], fmt)
                            from ulpf.utils import iso as _iso
                            result.event_time = dt
                        except ValueError:
                            pass
                    break
            if "host" in groups:
                result.host = groups["host"]
            elif "hostname" in groups:
                result.host = groups["hostname"]
            if "devname" in groups:
                result.host = result.host or groups["devname"]
            if "tag" in groups:
                result.attributes.setdefault("syslog.tag", groups["tag"])
            return result
        result.warnings.append("no configured regex matched")
        return result
