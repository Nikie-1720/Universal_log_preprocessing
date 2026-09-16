"""ULPF parser plugin package.

Built-in generic format parsers plus config-driven (YAML) vendor parsers are
wired together in ulpf.registry.
"""
from ulpf.parsers.base import ParseResult, Parser
from ulpf.parsers.cef_parser import CEFParser
from ulpf.parsers.csv_parser import CSVParser
from ulpf.parsers.json_parser import JSONParser
from ulpf.parsers.kv_parser import KVParser
from ulpf.parsers.leef_parser import LEEFParser
from ulpf.parsers.plain_parser import PlainParser
from ulpf.parsers.regex_parser import RegexParser
from ulpf.parsers.syslog_parser import SyslogParser
from ulpf.parsers.xml_parser import XMLParser

BUILTIN_CLASSES = {
    "syslog": SyslogParser,
    "json": JSONParser,
    "cef": CEFParser,
    "leef": LEEFParser,
    "kv": KVParser,
    "csv": CSVParser,
    "xml": XMLParser,
    "regex": RegexParser,
    "plain": PlainParser,
}

# Fixed priorities for generic built-ins (vendor YAML specs default to 50)
BUILTIN_PRIORITIES = {
    "syslog": 10, "xml": 12, "json": 15, "cef": 20, "leef": 20,
    "kv": 30, "csv": 5,
}

__all__ = [
    "ParseResult", "Parser", "BUILTIN_CLASSES", "BUILTIN_PRIORITIES",
    "SyslogParser", "JSONParser", "CEFParser", "LEEFParser", "KVParser",
    "CSVParser", "XMLParser", "RegexParser", "PlainParser",
]
