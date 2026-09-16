from tests.test_normalizer import build_event
import pprint

raw = '{"ts":"2026-02-14T09:30:04Z","level":"WARN","src_ip":"203.0.113.50","username":"jsmith","message":"Failed login"}'

ev = build_event(raw)
pprint.pp(ev["ues"])
