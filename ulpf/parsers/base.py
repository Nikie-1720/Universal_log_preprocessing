"""Parser plugin base classes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParseResult:
    """Everything a parser can extract from one raw record."""
    attributes: dict = field(default_factory=dict)   # verbatim, source-specific fields
    message: str = ""                                # human-readable message if found
    event_time: Any = None                           # raw timestamp value (datetime or str)
    host: str | None = None                          # envelope host (syslog host, etc.)
    pri: int | None = None                           # syslog priority value
    hints: dict = field(default_factory=dict)        # vendor/product/severity hints
    sub_raw: str | None = None                       # payload worth chained parsing
    warnings: list = field(default_factory=list)

    def merge(self, other: "ParseResult") -> None:
        self.attributes = {**self.attributes, **other.attributes}
        if other.message:
            self.message = other.message
        if self.event_time is None:
            self.event_time = other.event_time
        if self.host is None:
            self.host = other.host
        if self.pri is None and other.pri is not None:
            self.pri = other.pri
        self.hints.update(other.hints)
        self.warnings.extend(other.warnings)


class Parser:
    """Base class for all ULPF parser plugins.

    Subclasses implement `match()` (0.0..1.0 confidence) and `parse()`.
    Plugins must never raise from `parse()` for malformed input - return a
    ParseResult with warnings instead. ULPF guarantees the raw event survives.
    """
    id: str = "base"
    format_name: str = "base"
    priority: int = 10

    def __init__(self, options: dict | None = None):
        self.options = options or {}

    def match(self, raw: str) -> float:
        return 0.0

    def parse(self, raw: str) -> ParseResult:
        raise NotImplementedError

    def __repr__(self):  # pragma: no cover
        return f"<Parser {self.id}>"
