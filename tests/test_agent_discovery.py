import json
import platform

from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

import discovery


def test_discovery_is_explicitly_offline(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    report = discovery.discover([])
    assert report["offline"] is True
    assert report["network_access_required"] is False
    assert "os-detection" in report["capabilities"]


def test_custom_file_is_discovered(tmp_path):
    f = tmp_path / "sample.log"
    f.write_text("hello\n", encoding="utf-8")
    report = discovery.discover([str(f)])
    assert any(s.get("path") == str(f) and s["kind"] == "file" for s in report["sources"])


def test_report_is_json_serializable():
    report = discovery.discover([])
    json.dumps(report)
