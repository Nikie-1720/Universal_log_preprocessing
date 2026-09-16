"""A tiny YAML-subset loader so ULPF stays 100% standard-library (air-gap ready).

Supported subset (covers all shipped ULPF configs):
  * nested mappings via indentation (spaces only)
  * lists with '- ' items (scalars, inline maps, or nested blocks)
  * inline maps  {key: value, key2: value2}
  * inline lists [a, b, "c d"]
  * scalars: null/~, true/false, ints, floats
  * single-quoted strings are literal (backslashes kept) - use for regexes
  * double-quoted strings support \\\\, \\", \\n, \\t, \\r
  * '#' comments when at line start or preceded by whitespace

Not supported (not needed for ULPF configs): anchors/aliases, block scalars
(|, >), multi-line strings, tab indentation.
"""
from __future__ import annotations

from typing import Any


class YAMLError(ValueError):
    pass


def loads(text: str) -> Any:
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw).replace("\t", "  ")
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    if not lines:
        return {}
    parser = _BlockParser(lines)
    return parser.parse_block(lines[0][0])


def _strip_comment(line: str) -> str:
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in "\"'":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                return line[:i]
        i += 1
    return line


def _split_key(content: str):
    """Split 'key: rest' at the first unquoted colon followed by space or EOL."""
    quote = None
    i = 0
    while i < len(content):
        ch = content[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in "\"'":
                quote = ch
            elif ch == ":" and (i + 1 == len(content) or content[i + 1] == " "):
                return _scalar(content[:i].strip()), True, content[i + 1:].strip()
        i += 1
    return None, False, content


def _scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    first = text[0]
    if first in "\"'":
        return _unquote(text)
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(part) for part in _split_top(text[1:-1])]
    if text.startswith("{") and text.endswith("}"):
        return _parse_inline_map(text[1:-1])
    low = text.lower()
    if low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(text, 10)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _unquote(text: str) -> str:
    q = text[0]
    if len(text) < 2 or text[-1] != q:
        raise YAMLError(f"unterminated quoted string: {text!r}")
    body = text[1:-1]
    if q == "'":
        return body.replace("''", "'")
    out = []
    escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            out.append(escapes.get(body[i + 1], body[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_top(body: str, sep: str = ","):
    """Split on `sep` at depth 0, respecting quotes and nested [] {}."""
    parts, buf = [], []
    depth = 0
    quote = None
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            buf.append(ch)
            if quote == '"' and ch == "\\":
                if i + 1 < len(body):
                    buf.append(body[i + 1])
                    i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _parse_inline_map(body: str) -> dict:
    result = {}
    for part in _split_top(body):
        key, found, rest = _split_key(part)
        if not found:
            raise YAMLError(f"invalid inline map entry: {part!r}")
        result[key] = _scalar(rest)
    return result


class _BlockParser:
    def __init__(self, lines):
        self.lines = lines
        self.pos = 0

    def parse_block(self, indent: int) -> Any:
        content = self.lines[self.pos][1]
        if content == "-" or content.startswith("- "):
            return self._parse_list(indent)
        return self._parse_map(indent)

    def _parse_map(self, indent: int) -> dict:
        result = {}
        while self.pos < len(self.lines):
            cur_indent, content = self.lines[self.pos]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                raise YAMLError(f"unexpected indent: {content!r}")
            if content == "-" or content.startswith("- "):
                break
            key, found, rest = _split_key(content)
            if not found:
                raise YAMLError(f"expected 'key: value' line: {content!r}")
            self.pos += 1
            if rest == "":
                nxt = self.lines[self.pos] if self.pos < len(self.lines) else None
                if nxt and nxt[0] > indent:
                    result[key] = self.parse_block(nxt[0])
                elif nxt and nxt[0] == indent and (nxt[1] == "-" or nxt[1].startswith("- ")):
                    # list items at the same indent as their parent key
                    result[key] = self._parse_list(indent)
                else:
                    result[key] = None
            else:
                result[key] = _scalar(rest)
        return result

    def _parse_list(self, indent: int) -> list:
        result = []
        while self.pos < len(self.lines):
            cur_indent, content = self.lines[self.pos]
            if cur_indent != indent or not (content == "-" or content.startswith("- ")):
                break
            item = content[1:].strip()
            self.pos += 1
            if not item:
                nxt = self.lines[self.pos] if self.pos < len(self.lines) else None
                if nxt and nxt[0] > indent:
                    result.append(self.parse_block(nxt[0]))
                else:
                    result.append(None)
                continue
            key, found, rest = _split_key(item)
            if found:
                # '- key: value' starts a mapping whose keys align after '- '
                item_indent = indent + 2
                self.lines.insert(self.pos, (item_indent, item))
                result.append(self._parse_map(item_indent))
            else:
                result.append(_scalar(item))
        return result
