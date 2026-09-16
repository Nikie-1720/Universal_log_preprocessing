"""JSON log parser (single-line JSON objects/arrays)."""
from __future__ import annotations

import json

from ulpf.parsers.base import ParseResult, Parser
from ulpf.utils import flatten_json

MESSAGE_KEYS = ("msg", "message", "text", "event", "description", "summary")
TIME_KEYS = ("timestamp", "@timestamp", "time", "eventtime", "event_time", "datetime", "ts", "date")
HOST_KEYS = ("host", "hostname", "computer", "device", "host.name", "devname")
LEVEL_KEYS = ("level", "loglevel", "severity", "sev")
SERVICE_KEYS = ("service", "logger", "appname", "program", "application")


class JSONParser(Parser):
    id = "json"
    format_name = "json"
    priority = 15

    def match(self, raw: str) -> float:
        line = raw.strip()
        if not (line.startswith("{") or line.startswith("[")):
            return 0.0
        try:
            obj = json.loads(line)
        except ValueError:
            return 0.0
        return 0.95 if isinstance(obj, (dict, list)) else 0.0

    def parse(self, raw: str) -> ParseResult:
        result = ParseResult()
        try:
            obj = json.loads(raw.strip())
        except ValueError as ex:
            result.warnings.append(f"json decode error: {ex}")
            return result
        if isinstance(obj, dict):
            result.attributes = flatten_json(obj)
        elif isinstance(obj, list):
            result.attributes = {"items": obj}
        low = {k.lower(): v for k, v in result.attributes.items()}
        for k in MESSAGE_KEYS:
            if k in low and isinstance(low[k], str):
                result.message = low[k]
                break
        for k in TIME_KEYS:
            if k in low:
                result.event_time = low[k]
                break
        for k in HOST_KEYS:
            if k in low and isinstance(low[k], str):
                result.host = low[k]
                break
        for k in LEVEL_KEYS:
            if k in low:
                result.hints["severity_raw"] = low[k]
                break
        for k in SERVICE_KEYS:
            if k in low and isinstance(low[k], str):
                result.hints["service"] = low[k]
                break
        return result
