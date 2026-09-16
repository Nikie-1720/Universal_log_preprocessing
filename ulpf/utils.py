"""Shared utilities for ULPF (standard library only)."""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import uuid

EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
_UTC = _dt.timezone.utc

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S:%f", "%b %d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y", "%Y%m%d%H%M%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S",
)


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_UTC)


def iso(dt: _dt.datetime | None) -> str | None:
    """Render a datetime as ISO-8601 UTC with millisecond precision and Z suffix."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_UTC)
    dt = dt.astimezone(_UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + ("%03dZ" % (dt.microsecond // 1000))


def now_iso() -> str:
    return iso(utc_now())


def epoch_ms(dt: _dt.datetime | None) -> int | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_UTC)
    return int((dt - EPOCH).total_seconds() * 1000)


def parse_timestamp(value, year: int | None = None) -> _dt.datetime | None:
    """Parse the many timestamp shapes found in logs into an aware UTC datetime.

    Handles epoch seconds/millis/micros/nanos (int or str), ISO-8601, syslog
    variants, nginx/CEF style formats.  Year-less values are assumed to be from
    the current year (or `year` if given).  Timezone-less values are assumed UTC.
    """
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _from_epoch(float(value))
    s = str(value).strip()
    if not s or s == "-":
        return None
    # Epoch numeric strings (10/13/16/19 digits, optional fractional seconds)
    if re.fullmatch(r"\d{9,10}(\.\d+)?", s):
        return _from_epoch(float(s))
    if re.fullmatch(r"\d{13}(\.\d+)?", s):
        return _from_epoch(float(s) / 1000.0)
    if re.fullmatch(r"\d{16}", s):
        return _from_epoch(float(s) / 1_000_000.0)
    if re.fullmatch(r"\d{19}", s):
        return _from_epoch(float(s) / 1_000_000_000.0)
    candidates = [s, re.sub(r"\s+", " ", s)]
    iso_s = s.strip()
    if iso_s.endswith("Z"):
        iso_s = iso_s[:-1] + "+00:00"
    candidates.append(iso_s)
    for cand in candidates:
        try:
            return _dt.datetime.fromisoformat(cand).replace(tzinfo=(_dt.datetime.fromisoformat(cand).tzinfo or _UTC)).astimezone(_UTC)
        except (ValueError, TypeError):
            pass
    for fmt in _TS_FORMATS:
        for cand in candidates:
            try:
                dt = _dt.datetime.strptime(cand, fmt)
            except (ValueError, TypeError):
                continue
            if dt.tzinfo is None:
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = dt.replace(year=(year or utc_now().year))
                dt = dt.replace(tzinfo=_UTC)
            return dt.astimezone(_UTC)
    return None


def _from_epoch(seconds: float) -> _dt.datetime:
    try:
        return _dt.datetime.fromtimestamp(seconds, tz=_UTC)
    except (OverflowError, OSError, ValueError):
        return None


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


def set_path(d: dict, dotted: str, value) -> None:
    """Set a nested value using a dotted path, creating intermediate dicts."""
    if value is None:
        return
    parts = dotted.split(".")
    cur = d
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def get_path(d: dict, dotted: str, default=None):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def set_u(event: dict, dotted: str, value) -> None:
    """Set a UES taxonomy path (or a trace.* path) on an event."""
    if value is None:
        return
    if dotted.startswith("trace."):
        set_path(event, dotted, value)
    else:
        set_path(event["ues"], dotted, value)


def get_u(event: dict, dotted: str, default=None):
    if dotted.startswith("trace."):
        return get_path(event, dotted, default)
    return get_path(event.get("ues", {}), dotted, default)


def flatten_json(obj, prefix: str = "", sep: str = ".") -> dict:
    """Flatten nested JSON objects into dotted keys (lists kept as values)."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{sep}{k}" if prefix else str(k)
            if isinstance(v, dict) and v:
                out.update(flatten_json(v, key, sep))
            else:
                out[key] = v
    return out


def is_internal_ip(ip_str: str) -> bool | None:
    """True if the address is private/loopback/link-local, False if public, None if invalid."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return None
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def ip_to_int(ip_str: str) -> int | None:
    try:
        return int(ipaddress.ip_address(str(ip_str).strip()))
    except ValueError:
        return None


def parse_size(text) -> int:
    """Parse human sizes like '10MB', '512K', '1GB' into bytes."""
    if isinstance(text, (int, float)):
        return int(text)
    s = str(text).strip().upper().replace(" ", "")
    m = re.fullmatch(r"([\d.]+)([KMGT]?I?B?)", s)
    if not m:
        raise ValueError(f"invalid size: {text!r}")
    num = float(m.group(1))
    unit = m.group(2).rstrip("B").replace("I", "")
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}.get(unit, 1)
    return int(num * mult)


def expand_env(value: str) -> str:
    """Expand ${VAR} references from the environment."""
    if not isinstance(value, str):
        return value
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), value)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def iter_lines(path: str):
    """Iterate non-empty lines of a file with universal newline handling."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.strip():
                yield line


class _SafeDict(dict):
    def __missing__(self, key):  # leave unknown keys as-is
        return "{" + key + "}"


def safe_format(template: str, mapping: dict) -> str:
    return template.format_map(_SafeDict(mapping))


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def colorize(enabled: bool):
    class _C:
        def __getattr__(self, name):
            if not enabled or name.startswith("_"):
                return ""
            return getattr(Ansi, name, "")
    return _C()


def json_dumps(obj, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))


def is_ip(value) -> bool:
    """Return True when value is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def looks_like_base64(value) -> bool:
    """Conservative offline heuristic for base64-looking strings."""
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        return False
    if len(value) < 4 or len(value) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value))
