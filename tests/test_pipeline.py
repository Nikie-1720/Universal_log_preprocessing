"""Unit + end-to-end tests: pipeline core, runtime, config, CLI smoke tests."""
import json
import os
import subprocess
import sys
import time

import pytest

from ulpf.config import load_pipeline_config
from ulpf.pipeline import Pipeline, Runtime
from ulpf.utils import iter_lines

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_pipeline():
    cfg = load_pipeline_config(os.path.join(ROOT, "configs", "pipeline.yaml"))
    from ulpf.enricher import build_enrichers
    from ulpf.registry import ParserRegistry
    from ulpf.config import load_parser_specs
    specs = load_parser_specs(cfg)
    return Pipeline(cfg, registry=ParserRegistry(specs), enrichers=build_enrichers(cfg))


def test_pipeline_end_to_end_all_samples():
    p = make_pipeline()
    samples = sorted(os.path.join(ROOT, "samples", f)
                     for f in os.listdir(os.path.join(ROOT, "samples")))
    assert samples, "no sample files"
    parsed = failed = 0
    for f in samples:
        for raw in iter_lines(f):
            ev = p.process_raw(raw, {"source_type": "file", "address": f})
            assert ev["raw"] == raw, "raw preservation violated"
            assert ev["trace"]["raw_hash"]
            if ev["meta"]["parse_status"] == "parsed":
                parsed += 1
            else:
                failed += 1
                print("FAILED:", f, raw[:80], ev["meta"]["warnings"])
    total = parsed + failed
    assert total > 30
    assert parsed / total >= 0.9, f"parse success rate too low: {parsed}/{total}"


def test_pipeline_threat_hit():
    p = make_pipeline()
    ev = p.process_raw('{"ts":"2026-02-14T09:00:00Z","src_ip":"198.51.100.23","message":"evil"}')
    assert (ev["ues"].get("threat") or {}).get("matched")


def test_pipeline_runtime_files(tmp_path):
    cfg = load_pipeline_config(os.path.join(ROOT, "configs", "pipeline.yaml"))
    cfg["inputs"] = [{"type": "file", "path": os.path.join(ROOT, "samples", "app-json.log")}]
    out_path = tmp_path / "rt.jsonl"
    cfg["outputs"] = [{"type": "jsonl", "path": str(out_path)}]
    rt = Runtime(cfg)
    rt.start()
    time.sleep(1.5)
    stats = rt.shutdown()
    assert stats["counters"]["received"] >= 4
    assert stats["counters"]["parsed"] >= 4
    lines = out_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 4


def test_cli_help():
    r = subprocess.run([sys.executable, "-m", "ulpf", "--help"],
                       capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert r.returncode == 0
    assert "parse" in r.stdout


def test_cli_parse_stdout():
    r = subprocess.run([sys.executable, "-m", "ulpf", "parse",
                        os.path.join("samples", "app-json.log"), "--limit", "2",
                        "--no-color"],
                       capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert r.returncode == 0
    assert "parse summary" in r.stderr


def test_cli_validate_with_sample():
    r = subprocess.run([sys.executable, "-m", "ulpf", "validate",
                        "--file", os.path.join("samples", "syslog-sshd.log"), "--no-color"],
                       capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_doctor():
    r = subprocess.run([sys.executable, "-m", "ulpf", "doctor", "--no-color"],
                       capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_parse_to_sqlite(tmp_path):
    db = tmp_path / "t.db"
    r = subprocess.run([sys.executable, "-m", "ulpf", "parse",
                        os.path.join("samples", "cef-firewall.log"),
                        "--output", f"sqlite:{db}", "--no-color"],
                       capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    import sqlite3
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    assert n == 3
