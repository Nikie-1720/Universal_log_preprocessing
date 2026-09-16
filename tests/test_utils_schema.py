"""Unit tests: utils and schema helpers."""
import pytest

from ulpf.utils import (iso, new_id, now_iso, parse_timestamp, safe_format, set_u, get_u,
                        sha256_hex, is_ip, looks_like_base64)
from ulpf.schema import severity_label_and_number, SYSLOG_PRI_LABELS


def test_parse_timestamp_iso():
    dt = parse_timestamp("2026-02-14T09:30:01Z")
    assert dt is not None and dt.year == 2026


def test_parse_timestamp_syslog():
    dt = parse_timestamp("Feb 14 09:23:01")
    assert dt is not None and dt.month == 2 and dt.day == 14


def test_parse_timestamp_epoch():
    dt = parse_timestamp("1739521201")
    assert dt is not None and dt.year in (2025, 2026)


def test_parse_timestamp_garbage():
    assert parse_timestamp("not a date") is None
    assert parse_timestamp("") is None
    assert parse_timestamp(None) is None


def test_iso_roundtrip():
    dt = parse_timestamp("2026-02-14T09:30:01Z")
    s = iso(dt)
    assert s.endswith("Z") or "+00:00" in s


def test_new_id_unique():
    ids = {new_id() for _ in range(200)}
    assert len(ids) == 200


def test_sha256_hex():
    h = sha256_hex("abc")
    assert h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_set_get_u():
    ev = {}
    set_u(ev, "source.ip", "1.2.3.4")
    assert ev["source"]["ip"] == "1.2.3.4"
    assert get_u(ev, "source.ip") == "1.2.3.4"
    assert get_u(ev, "no.such.path") is None


def test_safe_format():
    out = safe_format("user {user} from {ip}", {"user": "bob", "ip": "1.2.3.4"})
    assert out == "user bob from 1.2.3.4"
    out2 = safe_format("missing {nope} ok", {"a": 1})
    assert "nope" in out2 or out2 == "missing {nope} ok"


def test_is_ip():
    assert is_ip("10.0.0.1")
    assert is_ip("::1")
    assert not is_ip("not-an-ip")
    assert not is_ip("999.1.1.1")


def test_looks_like_base64():
    assert looks_like_base64("aGVsbG8=")
    assert not looks_like_base64("hello world with spaces!")


def test_severity_map():
    assert severity_label_and_number("emerg") == ("critical", 5)
    assert severity_label_and_number("alert") == ("critical", 5)
    assert severity_label_and_number("critical") == ("critical", 5)
    assert severity_label_and_number("err") == ("high", 4)
    assert severity_label_and_number("error") == ("high", 4)
    assert severity_label_and_number("warn") == ("medium", 3)
    assert severity_label_and_number("notice") == ("low", 2)
    assert severity_label_and_number("info") == ("info", 1)
    assert severity_label_and_number("debug") == ("debug", 1)
    assert severity_label_and_number("unknown-thing") == (None, None)


def test_syslog_pri_labels():
    assert SYSLOG_PRI_LABELS[0] == "emergency"
    assert SYSLOG_PRI_LABELS[7] == "debug"
