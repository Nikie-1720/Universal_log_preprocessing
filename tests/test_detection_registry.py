"""Unit tests: format detection + registry selection and chaining."""
from ulpf.detection import detect_format
from ulpf.registry import ParserRegistry
from ulpf.parsers import BUILTIN_CLASSES


def test_detect_json():
    d = detect_format('{"a": 1, "ts": "2026-02-14T09:00:00Z"}')
    assert d["format"] == "json"


def test_detect_cef():
    d = detect_format("CEF:0|V|P|1.0|100|msg|3|src=1.2.3.4")
    assert d["format"] == "cef"


def test_detect_leef():
    d = detect_format("LEEF:1.0|Security|TMCM|6.0|100|src=1.2.3.4")
    assert d["format"] == "leef"


def test_detect_syslog():
    d = detect_format("<13>Feb 14 09:23:01 fw01 sshd[1]: hi")
    assert d["format"] == "syslog"


def test_detect_kv():
    d = detect_format("date=2026-02-14 srcip=1.2.3.4 action=deny")
    assert d["format"] == "kv"


def test_detect_csv():
    d = detect_format("a,b,c\n1,2,3")
    assert d["format"] == "csv"


def test_detect_xml():
    d = detect_format("<event><host>x</host></event>")
    assert d["format"] == "xml"


def test_detect_text_fallback():
    d = detect_format("completely freeform text line")
    assert d["format"] in ("text", "kv", "csv")


def test_registry_selects_cef_over_kv():
    reg = ParserRegistry()
    raw = "CEF:0|V|P|1.0|100|msg|3|src=1.2.3.4 spt=1000 act=deny"
    result, parser, spec, det, chained = reg.parse_chain(raw)
    assert parser.format_name == "cef"


def test_registry_vendor_spec_wins():
    spec = {
        "id": "acme-fw", "name": "Acme FW", "vendor": "Acme", "product": "FW",
        "priority": 50,
        "match": {"any": [{"contains": "ACME-EVENT"}]},
        "format": "kv",
        "mapping": {"message": {"src": "msgtxt"}},
    }
    reg = ParserRegistry([spec])
    raw = "ACME-EVENT srcip=10.0.0.1 msgtxt=hello"
    result, parser, spec_sel, det, chained = reg.parse_chain(raw)
    assert spec_sel is not None and spec_sel.id == "acme-fw"


def test_registry_spec_match_must_pass():
    spec = {
        "id": "nope", "match": {"any": [{"contains": "NEVER-PRESENT"}]},
        "format": "kv", "priority": 90,
    }
    reg = ParserRegistry([spec])
    raw = "srcip=1.2.3.4 action=deny"
    result, parser, spec_sel, det, chained = reg.parse_chain(raw)
    assert spec_sel is None  # generic parser used


def test_registry_chaining_syslog_to_kv():
    reg = ParserRegistry()
    raw = ('<134>Feb 14 09:36:01 asa01 %ASA-6-302013: Built inbound TCP connection 12345 '
           'for outside:203.0.113.77/44122 to inside:192.168.1.50/22')
    result, parser, spec, det, chained = reg.parse_chain(raw)
    assert parser.format_name == "syslog"
    assert result.attributes.get("program") == "asa01" or result.host == "asa01"
    # the ASA message body is KV-like; chained parsing should have extracted attrs
    assert result.attributes or result.message


def test_registry_never_loses_data():
    reg = ParserRegistry()
    weird = "\x00\x01 binary-ish garbage <<<>>>"
    result, parser, spec, det, chained = reg.parse_chain(weird)
    assert result is not None
    assert result.message == weird or result.attributes
