"""Canonical taxonomy knowledge: severity aliases, action synonyms, keyword
classifiers, and the key-inference table used to normalize un-mapped fields.
"""
from __future__ import annotations

import re

# Canonical action synonyms -> UES action
ACTION_SYNONYMS = {
    "allow": "allow", "accept": "allow", "accept ": "allow", "permit": "allow",
    "forward": "allow", "pass": "allow", "start": "allow", "built": "allow",
    "open": "allow", "teardown": "allow", "allow": "allow",
    "deny": "deny", "denied": "deny", "deny ": "deny", "block": "deny",
    "blocked": "deny", "drop": "deny", "dropped": "deny", "reject": "deny",
    "reset": "deny", "reset-both": "deny", "refused": "deny", "block-url": "deny",
    "alert": "alert", "detect": "alert", "monitor": "alert",
    "quarantine": "quarantine", "isolate": "quarantine",
}

OUTCOME_FAILURE_KEYWORDS = re.compile(
    r"\b(failed|failure|denied|denie[sd]|refused|rejected|blocked|unauthorized|"
    r"invalid user|bad credentials|error|reset by peer|timed out|drop|abort)\b", re.I)
OUTCOME_SUCCESS_KEYWORDS = re.compile(
    r"\b(accepted|allowed|succeeded|success|established|built|connected|granted|opened)\b", re.I)

CATEGORY_RULES = [
    ("authentication", re.compile(r"(failed password|accepted password|accepted publickey|"
                                  r"authentication|sshd|sudo|logon|logoff|login session|user session|"
                                  r"invalid user|credentials)", re.I)),
    ("malware", re.compile(r"(worm|virus|malware|trojan|ransomware|botnet|\bc2\b|c&c|"
                           r"command and control|exploit)", re.I)),
    ("web", re.compile(r"(https?/|wp-login|\bhttp\b)", re.I)),
    ("network", re.compile(r"\b(tcp|udp|icmp|connection|session|firewall|acl)\b", re.I)),
    ("application", re.compile(r"(exception|unhandled|stack trace|nullpointer|timeout|"
                               r"crash|out of memory|discarded|gateway)", re.I)),
]

TYPE_FROM_CATEGORY = {
    "network": "connection",
    "authentication": "login",
    "web": "http",
    "malware": "malware",
    "system": "system",
    "application": "app_event",
    "database": "query",
    "cloud": "cloud_event",
}

# syslog PRI severity (pri % 8) -> canonical label
SYSLOG_PRI_LABELS = ["critical", "critical", "critical", "high", "medium", "info", "info", "debug"]

# ---- key inference table -----------------------------------------------------
# (ues_target, [candidate raw keys (lowercase)], converter_type)
# Lets generic JSON/KV/CEF/LEEF logs normalize without any per-vendor mapping.
INFERENCE = [
    ("event_time", ["timestamp", "@timestamp", "time", "eventtime", "event_time", "datetime",
                    "_time", "generated_time", "date", "ts", "receive_time", "rt"], "timestamp"),
    ("severity_label", ["level", "loglevel", "severity", "sev", "log_level"], "loglevel"),
    ("message", ["msg", "message", "text", "event", "description", "summary"], "str"),
    ("service", ["service", "appname", "program", "application_name"], "str"),
    ("action", ["action", "act", "verdict", "disposition", "decision", "result"], "action"),
    ("outcome", ["outcome", "status_desc", "auth_result"], "str"),
    ("source.ip", ["src", "srcip", "src_ip", "source_ip", "sourceip", "clientip", "client_ip",
                   "c-ip", "srcaddr", "s-ip", "src_ip", "source.ip", "client.address"], "ip"),
    ("source.port", ["srcport", "src_port", "source_port", "spt", "sport", "clientport",
                     "source.port"], "int"),
    ("source.zone", ["srcintf", "src_zone", "source_zone", "in_if", "srcintfzone"], "str"),
    ("destination.ip", ["dst", "dstip", "dst_ip", "dest_ip", "destip", "destination_ip",
                        "daddr", "d-ip", "serverip", "server_ip", "destination.ip"], "ip"),
    ("destination.port", ["dstport", "dst_port", "dest_port", "dpt", "dport", "serverport",
                          "destination.port"], "int"),
    ("destination.zone", ["dstintf", "dst_zone", "destination_zone", "out_if"], "str"),
    ("destination.service", ["service", "dstservice", "service_name"], "str"),
    ("network.transport", ["proto", "protocol", "transport", "ip_proto", "network.transport"], "proto"),
    ("network.session_id", ["sessionid", "session_id", "connection", "conn_id", "connection_id"], "str"),
    ("network.bytes_in", ["rcvdbyte", "bytes_in", "inbytes", "bytes_received", "rbytes"], "int"),
    ("network.bytes_out", ["sentbyte", "bytes_out", "outbytes", "bytes_sent", "sbytes"], "int"),
    ("network.packets", ["pkts", "packets", "total_packets"], "int"),
    ("network.duration", ["duration", "duration_s", "elapsed"], "float"),
    ("network.direction", ["direction", "dir"], "str"),
    ("network.application", ["application", "app", "app_proto"], "str"),
    ("user.name", ["user", "username", "srcuser", "duser", "suser", "usr", "user.name", "acct"], "str"),
    ("user.domain", ["domain", "user_domain", "ntdomain"], "str"),
    ("device.host", ["devname", "dvc", "dvchost", "computer", "device.host", "syslog_host",
                     "device_name", "host.name"], "str"),
    ("device.vendor", ["vendor", "device.vendor"], "str"),
    ("device.product", ["product", "device.product", "deviceproduct"], "str"),
    ("process.pid", ["pid", "processid", "process_id", "process.pid"], "int"),
    ("process.name", ["process", "process_name", "proc", "process.name"], "str"),
    ("http.method", ["method", "cs-method", "reqmethod", "http.method"], "str"),
    ("http.url", ["url", "request", "cs-uri", "uri", "cs-uri-stem", "http.url", "req"], "str"),
    ("http.host", ["http.host", "vhost", "cs-host", "http_host"], "str"),
    ("http.status_code", ["status", "status_code", "sc-status", "respcode", "http.status_code"], "int"),
    ("http.bytes", ["sc-bytes", "resp_len", "http.bytes"], "int"),
    ("http.user_agent", ["user_agent", "useragent", "cs-user-agent", "http.user_agent"], "str"),
    ("http.referrer", ["referrer", "referer", "cs-referer", "http.referrer"], "str"),
    ("dns.query", ["dns_query", "dns.query", "query", "qname"], "str"),
    ("file.name", ["file", "fname", "filename", "file.name", "malware_url"], "str"),
    ("trace.correlation_id", ["trace_id", "traceid", "correlation_id", "request_id"], "str"),
]

# Fast lookup: lowercase raw key -> (target, type)
INFERENCE_BY_KEY = {}
for _target, _keys, _ctype in INFERENCE:
    _keys = list(_keys) + [_target]
    for _k in _keys:
        INFERENCE_BY_KEY.setdefault(_k, (_target, _ctype))
