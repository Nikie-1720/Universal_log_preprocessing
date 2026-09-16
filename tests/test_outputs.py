"""Unit tests: output sinks."""
import json
import os
import sqlite3

import pytest

from ulpf.outputs import (JsonlOutput, RawArchiveOutput, SqliteOutput, StdoutOutput,
                          build_outputs)


def sample_event():
    return {"raw": "line one", "ues": {"event_id": "e1", "event_time": "2026-02-14T09:00:00Z",
                                       "severity": 3, "severity_label": "medium",
                                       "category": "network", "action": "deny",
                                       "outcome": "failure", "message": "m"},
            "meta": {"parser": "kv", "format": "kv", "parse_status": "parsed",
                     "pipeline_id": "t", "warnings": []},
            "trace": {"trace_id": "t1", "raw_hash": "abc", "raw_size": 8, "algorithm": "sha256"}}


def test_stdout_output(capsys):
    out = StdoutOutput({})
    out.open()
    out.write([sample_event()])
    out.flush()
    captured = capsys.readouterr()
    assert "event_id" in captured.out


def test_jsonl_output(tmp_path):
    path = tmp_path / "out.jsonl"
    out = JsonlOutput({"path": str(path)})
    out.open()
    out.write([sample_event(), sample_event()])
    out.close()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["raw"] == "line one"
    assert rec["ues"]["event_id"] == "e1"


def test_raw_archive_output(tmp_path):
    path = tmp_path / "raw"
    out = RawArchiveOutput({"path": str(path)})
    out.open()
    ev = sample_event()
    ev["raw"] = "raw-bytes-ünicode"
    out.write([ev])
    out.close()
    files = list(path.rglob("*.raw"))
    assert files, "raw archive file missing"
    content = files[0].read_text(encoding="utf-8")
    assert "raw-bytes-ünicode" in content


def test_sqlite_output(tmp_path):
    db = tmp_path / "events.db"
    out = SqliteOutput({"path": str(db)})
    out.open()
    out.write([sample_event()])
    out.flush()
    out.close()
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT source_ip, category, action FROM events").fetchone()
    assert row is not None
    conn.close()


def test_build_outputs_by_type():
    outs = build_outputs([{"type": "stdout"}, {"type": "null"}])
    assert len(outs) == 2


def test_unknown_output_type_raises():
    with pytest.raises(Exception):
        build_outputs([{"type": "definitely-not-a-sink"}])
