"""Focused hardening regressions executed in the release checkout."""
import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(code, env=None):
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = ROOT
    if env:
        child_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_release_plugin_contract_discovery():
    assert _run(
        "from ulpf.config import discover_plugins; "
        "p=discover_plugins(); assert p and all(x['status']=='valid' for x in p)"
    ) == ""


def test_auth_failure_is_not_generic_alert():
    output = _run(
        "from ulpf.web import evaluate_alerts; "
        "e={'ues': {'category':'authentication','outcome':'failure',"
        "'action':'deny','source':{'ip':'192.0.2.1'}},"
        "'trace':{'trace_id':'t','raw_hash':'h'},'meta':{}}; "
        "assert evaluate_alerts(e)==[]"
    )
    assert output == ""
