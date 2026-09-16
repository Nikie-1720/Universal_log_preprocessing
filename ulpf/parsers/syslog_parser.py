"""Syslog parser: RFC5424 (structured) and RFC3164 (BSD) envelope parsing.

Extracts the envelope (priority, timestamp, host, tag) and hands the message
body back to the pipeline for chained parsing (JSON/KV/CEF/... inside syslog).
"""
from __future__ import annotations

import re

from ulpf.parsers.base import ParseResult, Parser
from ulpf.utils import parse_timestamp

RE_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2})\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<sdata>(?:\[.*?\])*)\s*(?P<msg>.*)$", re.S)
RE_3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?:(?P<tag>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*)?(?P<msg>.*)$", re.S)

DASH = {"-", "NILVALUE"}


class SyslogParser(Parser):
    id = "syslog"
    format_name = "syslog"
    priority = 10

    def match(self, raw: str) -> float:
        line = raw.strip()
        if RE_5424.match(line):
            return 0.95
        if RE_3164.match(line):
            return 0.9
        return 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        line = raw.strip()
        m = RE_5424.match(line)
        if m:
            g = m.groupdict()
            result.pri = int(g["pri"])
            if g["ts"] not in DASH:
                result.event_time = parse_timestamp(g["ts"]) or g["ts"]
            if g["host"] not in DASH:
                result.host = g["host"]
            for key in ("app", "proc", "msgid"):
                if g[key] not in DASH:
                    result.attributes[f"syslog.{key}"] = g[key]
            if g["sdata"]:
                result.attributes["syslog.sdata"] = g["sdata"]
            result.sub_raw = g["msg"]
            result.message = g["msg"][:512]
            return result
        m = RE_3164.match(line)
        if m:
            g = m.groupdict()
            result.pri = int(g["pri"]) if g["pri"] else None
            result.event_time = parse_timestamp(g["ts"])
            result.host = g["host"]
            if g["tag"]:
                result.attributes["syslog.tag"] = g["tag"]
            if g["pid"]:
                result.attributes["syslog.pid"] = int(g["pid"])
            result.sub_raw = g["msg"]
            result.message = g["msg"][:512]
            return result
        result.warnings.append("unrecognized syslog envelope")
        result.message = line[:512]
        result.sub_raw = line
        return result
