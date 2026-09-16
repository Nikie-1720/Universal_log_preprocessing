"""Universal Event Schema (UES) v1.0.0 definition.

Every event flowing through ULPF is represented as:

{
  "ues":   { ...normalized, vendor-agnostic taxonomy fields... },
  "meta":  { ...pipeline/parser/source metadata... },
  "trace": { ...traceability: trace_id, raw hash/offset... },
  "raw":   "<the complete original log line - never modified>"
}

`raw` is always preserved, making the transformation lossless by construction.
"""
from __future__ import annotations

UES_VERSION = "1.0.0"

UES_SCHEMA = {
    "ues": {
        "schema_version": "UES version string, e.g. 1.0.0",
        "event_id": "UUID of this normalized event",
        "event_time": "ISO-8601 UTC event timestamp (normalized from source)",
        "event_time_epoch_ms": "event_time as epoch milliseconds",
        "ingest_time": "ISO-8601 UTC time the record was received by ULPF",
        "event_kind": "event | alert | telemetry | audit",
        "category": "network | authentication | web | malware | system | application | database | cloud",
        "type": "connection | login | http | dns | policy | malware | session | system",
        "action": "allow | deny | drop | reject | reset | block | alert | quarantine",
        "outcome": "success | failure | unknown",
        "severity": "0-100 numeric severity (canonical)",
        "severity_label": "debug | info | low | medium | high | critical",
        "message": "human-readable message",
        "service": "originating service/application name",
        "source": {"ip": "", "port": 0, "host": "", "zone": "", "user": "", "mac": ""},
        "destination": {"ip": "", "port": 0, "host": "", "zone": "", "service": ""},
        "user": {"name": "", "domain": ""},
        "network": {
            "transport": "tcp | udp | icmp ...",
            "protocol": "application protocol",
            "direction": "inbound | outbound | internal | external",
            "bytes_in": 0, "bytes_out": 0, "packets": 0,
            "duration": 0.0, "session_id": "", "application": "",
        },
        "http": {"method": "", "url": "", "host": "", "status_code": 0, "bytes": 0,
                 "user_agent": "", "referrer": ""},
        "dns": {"query": "", "answer": ""},
        "file": {"name": "", "path": "", "hash": ""},
        "process": {"name": "", "pid": 0, "command_line": ""},
        "device": {"host": "", "vendor": "", "product": "", "version": "", "zone": "", "interface": ""},
        "threat": {"matched": [{"indicator": "", "type": "", "severity": "", "feed": ""}], "score": 0},
        "geo": {
            "source": {"country": "", "city": "", "internal": True},
            "destination": {"country": "", "city": "", "internal": True},
        },
        "labels": {"arbitrary key/values from configs"},
        "tags": ["arbitrary string tags"],
    },
    "meta": {
        "pipeline_id": "logical pipeline name",
        "pipeline_version": "pipeline version",
        "parser": "parser plugin id that produced this event",
        "parser_chain": "list of chained parsers applied (e.g. syslog -> json)",
        "format": "detected raw format (json/cef/leef/syslog/kv/csv/xml/regex)",
        "parse_status": "parsed | failed",
        "detection": {"format": "", "confidence": 0.0, "reason": ""},
        "warnings": ["non-fatal normalization warnings"],
        "source_type": "syslog | file | stdin | http | kafka",
        "source_address": "peer address of the receiver",
        "source_transport": "udp | tcp | tls",
        "received_time": "ISO-8601 UTC receive time",
    },
    "trace": {
        "trace_id": "unique pipeline trace id",
        "correlation_id": "cross-source correlation id (e.g. application trace_id, session id)",
        "raw_hash": "sha256 of the raw event (integrity/forensics)",
        "raw_size": "raw size in bytes",
        "raw_offset": "byte offset of the raw event in its source file (when known)",
        "algorithm": "hash algorithm identifier",
    },
    "raw": "complete original event, never modified - lossless preservation",
}

SEVERITY_NUMBER = {"debug": 5, "info": 10, "low": 30, "medium": 50, "high": 70, "critical": 90}
SEVERITY_LABELS = list(SEVERITY_NUMBER)
SYSLOG_PRI_LABELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]


def severity_label_and_number(value):
    """Canonicalize any severity-ish value into (label, number 0-100).

    Numeric 0-10 is treated as the CEF scale; 11-100 as a direct percentage scale.
    """
    if value is None:
        return None, None
    if isinstance(value, (int, float)) or (isinstance(value, str) and str(value).strip().isdigit()):
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            return None, None
        n = max(0, min(100, n))
        return _label_from_number(n), n
    label = str(value).strip().lower()
    label = {"emerg": "critical", "emergency": "critical", "crit": "critical", "fatal": "critical",
             "err": "high", "error": "high", "alert": "high", "warning": "medium", "warn": "medium",
             "notice": "info", "informational": "info", "dbg": "debug"}.get(label, label)
    if label not in SEVERITY_NUMBER:
        return None, None
    return label, SEVERITY_NUMBER[label]


def _label_from_number(n: int) -> str:
    if n <= 10:
        if n <= 3:
            return "info"
        if n <= 5:
            return "low"
        if n <= 7:
            return "medium"
        if n <= 9:
            return "high"
        return "critical"
    if n >= 85:
        return "critical"
    if n >= 65:
        return "high"
    if n >= 45:
        return "medium"
    if n >= 20:
        return "low"
    return "info"
