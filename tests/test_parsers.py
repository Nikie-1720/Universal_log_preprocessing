"""Unit tests: built-in format parsers."""
import pytest

from ulpf.parsers import BUILTIN_CLASSES


def make(fmt, options=None):
    return BUILTIN_CLASSES[fmt](options or {})


def test_json_parser():
    p = make("json")
    assert p.match('{"a": 1}') > 0.5
    r = p.parse('{"timestamp":"2026-02-14T09:30:01Z","level":"ERROR","msg":"boom","x":1}')
    assert r.attributes["level"] == "ERROR"
    assert r.attributes["x"] == 1
    assert r.message == "boom"
    assert r.event_time.startswith("2026-02-14T09:30:01")


def test_json_parser_multiline_object():
    p = make("json")
    r = p.parse('{"ts": "2026-02-14T10:00:00Z", "nested": {"a": [1, 2]}}')
    assert r.attributes["nested"] == {"a": [1, 2]}


def test_syslog_parser_rfc3164():
    p = make("syslog")
    raw = "<13>Feb 14 09:23:01 fw01 sshd[2841]: Accepted password for admin from 203.0.113.77 port 51422 ssh2"
    assert p.match(raw) > 0.5
    r = p.parse(raw)
    assert r.pri == 13
    assert r.host == "fw01"
    assert r.attributes["program"] == "sshd"
    assert r.attributes["pid"] == 2841
    assert "Accepted password" in r.message


def test_syslog_parser_rfc5424():
    p = make("syslog")
    raw = ("<165>1 2026-02-14T09:23:01.003Z fw01 sshd 2841 - - BOM Accepted password "
           "for admin from 203.0.113.77 port 51422")
    r = p.parse(raw)
    assert r.pri == 165
    assert r.host == "fw01"
    assert r.event_time.startswith("2026-02-14T09:23:01")


def test_syslog_parser_sub_raw_for_chaining():
    p = make("syslog")
    raw = "<13>Feb 14 09:23:01 fw01 sshd[1]: Accepted password for admin from 203.0.113.77 port 51422 ssh2"
    r = p.parse(raw)
    assert r.sub_raw and "Accepted password" in r.sub_raw


def test_cef_parser():
    p = make("cef")
    raw = ('CEF:0|Vendor|Product|1.0|100|Traffic allowed|3|src=10.0.0.1 dst=93.184.216.34 '
           'spt=49152 dpt=443 proto=TCP act=allow suser=jsmith')
    assert p.match(raw) > 0.5
    r = p.parse(raw)
    assert r.attributes["deviceVendor"] == "Vendor"
    assert r.attributes["src"] == "10.0.0.1"
    assert r.attributes["spt"] == "49152"
    assert r.attributes["act"] == "allow"
    assert r.attributes["suser"] == "jsmith"


def test_cef_parser_escapes():
    p = make("cef")
    raw = r'CEF:0|V|P|1.0|1|E|5|msg=hello\=world path=C:\\temp\\x'
    r = p.parse(raw)
    assert r.attributes["msg"] == "hello=world"
    assert "\\" in r.attributes["path"]


def test_leef_parser():
    p = make("leef")
    raw = "LEEF:1.0|Security|TMCM|6.0|100|src=10.1.1.5|dst=93.184.216.34|sev=3"
    assert p.match(raw) > 0.5
    r = p.parse(raw)
    assert r.attributes["src"] == "10.1.1.5"
    assert r.attributes["dst"] == "93.184.216.34"
    assert r.attributes["sev"] == "3"
    assert r.attributes["LEEF_Vendor"] == "Security"


def test_leef_2_with_tab_delimiter():
    p = make("leef")
    raw = "LEEF:2.0|Security|TMCM|6.0|2004|\t".join(["src=10.1.1.9", "sev=9"]) 
    raw = "LEEF:2.0|Security|TMCM|6.0|2004|src=10.1.1.9\tsev=9"
    r = p.parse(raw)
    assert r.attributes["src"] == "10.1.1.9"
    assert r.attributes["sev"] == "9"


def test_kv_parser():
    p = make("kv")
    raw = 'date=2026-02-14 time=09:31:22 devname=FGT-EDGE srcip=192.168.1.50 action=close msg="Denied by policy"'
    assert p.match(raw) > 0.5
    r = p.parse(raw)
    assert r.attributes["devname"] == "FGT-EDGE"
    assert r.attributes["srcip"] == "192.168.1.50"
    assert r.attributes["msg"] == "Denied by policy"


def test_kv_parser_bracketed():
    p = make("kv")
    r = p.parse("date=2026-02-14 [tunnel=1] srcip=10.0.0.1")
    assert r.attributes["tunnel"] == "1"


def test_csv_parser():
    p = make("csv", {"columns": ["a", "b", "c"]})
    r = p.parse("1,2,3")
    assert r.attributes["a"] == "1"
    assert r.attributes["c"] == "3"


def test_csv_parser_with_header():
    p = make("csv", {"columns": "header"})
    r = p.parse("x,y\n10,20")
    assert r.attributes["x"] == "10"


def test_xml_parser():
    p = make("xml")
    raw = "<event><time>2026-02-14T09:34:01Z</time><host>esx01</host><msg>hi</msg></event>"
    r = p.parse(raw)
    assert r.attributes["host"] == "esx01"
    assert r.attributes["msg"] == "hi"


def test_regex_parser_named_groups():
    p = make("regex", {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<user>\w+) (?P<act>\w+)"})
    r = p.parse("10.0.0.5 alice login")
    assert r.attributes["ip"] == "10.0.0.5"
    assert r.attributes["user"] == "alice"
    assert r.attributes["act"] == "login"


def test_regex_parser_custom_field():
    p = make("regex", {"pattern": r"ip=(\S+)", "field": "client"})
    r = p.parse("ip=1.2.3.4")
    assert r.attributes["client"] == "1.2.3.4"


def test_plain_parser_always_parses():
    p = make("plain")
    r = p.parse("anything at all")
    assert r.message == "anything at all"
    assert p.match("anything") == 0.1


def test_parsers_never_raise():
    bad_inputs = ["", "   ", "\x00", "CEF:0|", "LEEF:", "{", "<a>", "a=1"]
    for fmt in BUILTIN_CLASSES:
        parser = BUILTIN_CLASSES[fmt]()
        for s in bad_inputs:
            try:
                parser.parse(s)
            except Exception as ex:  # pragma: no cover
                pytest.fail(f"{fmt} raised {ex!r} on {s!r}")
