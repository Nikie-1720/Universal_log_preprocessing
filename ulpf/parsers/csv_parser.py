"""CSV/DSV parser with column mapping, header support and delimiter sniffing."""
from __future__ import annotations

import csv
import io

from ulpf.parsers.base import ParseResult, Parser
from ulpf.taxonomy import INFERENCE_BY_KEY
from ulpf.utils import parse_timestamp


class CSVParser(Parser):
    id = "csv"
    format_name = "csv"
    priority = 5

    def match(self, raw: str) -> float:
        delim = self.options.get("delimiter")
        if not delim:
            try:
                delim = csv.Sniffer().sniff(raw, delimiters=",;\t|").delimiter
            except csv.Error:
                return 0.0
        return 0.5 if raw.count(delim) >= 2 else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        delim = self.options.get("delimiter")
        if not delim:
            try:
                delim = csv.Sniffer().sniff(raw, delimiters=",;\t|").delimiter
            except csv.Error:
                delim = ","
        reader = csv.reader(io.StringIO(raw), delimiter=delim,
                            quotechar=self.options.get("quotechar", '"'))
        rows = [row for row in reader if row]
        if not rows:
            result.warnings.append("empty csv row")
            return result
        row = rows[0]
        columns = self.options.get("columns")
        has_header = bool(self.options.get("has_header"))
        if has_header and len(rows) > 1:
            keys, values = rows[0], row if row is not rows[0] else rows[1]
            result.attributes = {str(k).strip(): v for k, v in zip(keys, values)}
        elif columns:
            attrs = {}
            for i, col in enumerate(columns):
                attrs[str(col)] = row[i] if i < len(row) else ""
            result.attributes = attrs
        else:
            result.attributes = {f"col_{i}": v for i, v in enumerate(row)}
        low = {k.lower(): v for k, v in result.attributes.items()}
        for key, (target, ctype) in INFERENCE_BY_KEY.items():
            if target == "event_time" and key in low:
                result.event_time = parse_timestamp(low[key]) or low[key]
                break
        for key in ("msg", "message", "text"):
            if key in low and isinstance(low[key], str):
                result.message = low[key]
                break
        return result
