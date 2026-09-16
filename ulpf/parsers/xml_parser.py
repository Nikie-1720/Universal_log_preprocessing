"""XML event parser (flattens elements to dotted attributes)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ulpf.parsers.base import ParseResult, Parser


def _flatten(node, prefix: str, out: dict) -> None:
    tag = node.tag.split("}")[-1]
    path = f"{prefix}.{tag}" if prefix else tag
    for attr, val in node.attrib.items():
        out[f"{path}@{attr}"] = val
    children = list(node)
    text = (node.text or "").strip()
    if not children:
        if text:
            out[path] = text
        return
    if text:
        out[path] = text
    groups = {}
    for child in children:
        groups.setdefault(child.tag, []).append(child)
    for tag2, nodes in groups.items():
        name = tag2.split("}")[-1]
        if len(nodes) == 1:
            _flatten(nodes[0], path, out)
        else:
            out[f"{path}.{name}"] = [(n.text or "").strip() for n in nodes]


class XMLParser(Parser):
    id = "xml"
    format_name = "xml"
    priority = 12

    def match(self, raw: str) -> float:
        line = raw.strip()
        if not line.startswith("<"):
            return 0.0
        try:
            ET.fromstring(line)
            return 0.9
        except ET.ParseError:
            return 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        try:
            root = ET.fromstring(raw.strip())
        except ET.ParseError as ex:
            result.warnings.append(f"xml parse error: {ex}")
            return result
        attrs = {}
        for attr, val in root.attrib.items():
            attrs[f"{root.tag}@{attr}"] = val
        for child in root:
            _flatten(child, "", attrs)
        result.attributes = attrs
        low = {k.lower(): v for k, v in attrs.items()}
        for k in ("timestamp", "eventtime", "time", "date", "datetime"):
            if k in low:
                result.event_time = low[k]
                break
        parts = [v for k, v in low.items() if isinstance(v, str)][:6]
        result.message = " ".join(parts)[:300]
        return result
