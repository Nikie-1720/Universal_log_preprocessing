"""Unit tests: normalizer, mapping DSL, conversions, inference, losslessness."""
from ulpf.normalizer import Normalizer, convert_value
from ulpf.registry import ParserRegistry
from ulpf.schema import severity_label_and_number


def build_event(raw, specs=None, source_meta=None):
    reg = ParserRegistry(specs or [])
    result, parser, spec, det, chained = reg.parse_chain(raw)
    norm = Normalizer()
    return norm.normalize(raw, source_meta or {}, result, parser, spec, det, chained)


def test_convert_value_types():
    assert convert_value("42", "int") == 42
    assert convert_value("3.5", "float") == 3.5
    assert convert_value("true", "bool") is True
    assert convert_value("10.0.0.1", "ip") == "10.0.0.1"
    assert convert_value("6", "proto") == "tcp"
    assert convert_value("17", "proto") == "udp"
    assert convert_value("Blocked", "lower") == "blocked"
    assert convert_value("allow", "action") == "allow"
    assert convert_value("DENIED", "action") == "denied"
    assert convert_value("2026-02-14T09:00:00Z", "timestamp").startswith("2026-02-14T09:00:00")


def test_convert_value_errors():
    import pytest
    from ulpf.normalizer import _ConversionError
    with pytest.raises(_ConversionError):
        convert_value("notanumber", "int")
    with pytest.raises(_ConversionError):
        convert_value("999.999.999.999", "ip")


def test_lossless_envelope():
    raw = "<13>Feb 14 09:23:01 fw01 sshd[2841]: Accepted password for admin from 203.0.113.77 port 51422 ssh2"
    ev = build_event(raw)
    assert ev["raw"] == raw
    assert ev["trace"]["raw_hash"]
    assert len(ev["trace"]["raw_hash"]) == 64
    assert ev["ues"]["event_id"]
    assert ev["ues"]["ingest_time"]


def test_severity_from_syslog_pri():
    raw = "<34>Feb 14 09:24:17 web01 sshd[2842]: Failed password for invalid user oracle from 198.51.100.23 port 44122 ssh2"
    ev = build_event(raw)
    # pri 34 -> facility 4, severity 2 -> crit
    assert ev["ues"]["severity_label"] == "crit"
    assert ev["ues"]["severity"] == 2


def test_auto_inference_ip_user():
    raw = ('{"ts":"2026-02-14T09:30:04Z","level":"WARN","src_ip":"203.0.113.50",'
           '"username":"jsmith","message":"Failed login"}')
    ev = build_event(raw)
    ues = ev["ues"]
    assert ues["source"]["ip"] == "203.0.113.50"
    assert ues["user"]["name"] == "jsmith"
    assert ues["severity_label"] == "warn"


def test_vendor_spec_mapping_dsl():
    spec = {
        "id": "acme", "match": {"any": [{"contains": "ACME-EVENT"}]},
        "format": "kv",
        "mapping": {
            "source.ip": {"src": "srcip", "type": "ip"},
            "destination.port": {"src": "dstport", "type": "port"},
            "event.action": {"src": "act", "type": "action"},
            "user.name": {"src": "suser"},
            "message": {"template": "acme {act} from {srcip}"},
        },
        "constants": {"category": "network", "device.vendor": "Acme"},
    }
    ev = build_event("ACME-EVENT srcip=10.0.0.1 dstport=22 act=BLOCKED suser=alice", [spec])
    ues = ev["ues"]
    assert ues["source"]["ip"] == "10.0.0.1"
    assert ues["destination"]["port"] == 22
    assert ues["event.action"] == "blocked"
    assert ues["user"]["name"] == "alice"
    assert ues["message"] == "acme BLOCKED from 10.0.0.1"
    assert ues["category"] == "network"
    assert ues["device"]["vendor"] == "Acme"


def test_severity_map_and_taxonomy():
    spec = {
        "id": "sevmap", "match": {"any": [{"contains": "SEVTEST"}]},
        "format": "kv",
        "severity": {"src": "lvl", "map": {"alert": "critical", "warn": "medium"},
                     "default": "info"},
        "taxonomy": {"event.category": {"src": "cat", "map": {"net": "network"}}},
    }
    ev = build_event("SEVTEST lvl=alert cat=net", [spec])
    assert ev["ues"]["severity_label"] == "critical"
    assert ev["ues"]["event.category"] == "network"


def test_derived_rules():
    spec = {
        "id": "derived", "match": {"any": [{"contains": "DERIVTEST"}]},
        "format": "kv",
        "derived": [
            {"when": r"attack=(?P<atk>[\w.]+)", "set": {"event.rule_name": {"value": "atk"}}},
            {"when": "Port.Scan", "set": {"tags": {"const": "scan"}}},
        ],
    }
    ev = build_event("DERIVTEST attack=TCP.Port.Scan", [spec])
    assert ev["ues"]["event.rule_name"] == "TCP.Port.Scan"
    assert "scan" in ev["ues"]["tags"]


def test_mapping_bad_value_becomes_warning_not_loss():
    spec = {
        "id": "bad", "match": {"any": [{"contains": "BADVAL"}]},
        "format": "kv",
        "mapping": {"source.port": {"src": "sport", "type": "port"}},
    }
    ev = build_event("BADVAL sport=notaport", [spec])
    assert ev["ues"]["source"].get("port") is None
    assert any("sport" in w for w in ev["meta"]["warnings"])


def test_failure_event_preserves_raw():
    norm = Normalizer()
    ev = norm.failure_event("some raw line", {"source_type": "test"}, None, "boom")
    assert ev["raw"] == "some raw line"
    assert ev["meta"]["parse_status"] == "failed"


def test_severity_label_and_number():
    assert severity_label_and_number("crit") == ("critical", 5)
    assert severity_label_and_number("err") == ("high", 4)
    assert severity_label_and_number("warning") == ("medium", 3)
    assert severity_label_and_number("7") == ("debug", 1)
