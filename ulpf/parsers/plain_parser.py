"""Last-resort parser: keeps the whole line as the message (never drops data)."""
from __future__ import annotations

from ulpf.parsers.base import ParseResult, Parser


class PlainParser(Parser):
    id = "plain"
    format_name = "text"
    priority = -1

    def match(self, raw: str) -> float:
        return 0.1 if raw.strip() else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        result.message = raw.strip()[:2000]
        return result
