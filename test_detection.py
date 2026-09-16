from ulpf.detection import detect_format

tests = {
    "JSON": '{"a": 1, "message": "test"}',

    "CEF": 'CEF:0|Vendor|Firewall|1.0|100|Denied|5|src=10.0.0.1',

    "LEEF": 'LEEF:1.0|Vendor|Product|1.0|100|src=10.0.0.1',

    "SYSLOG": '<13>Feb 14 09:23:01 fw01 sshd[1]: authentication failed',

    "KV": 'timestamp=2026-02-14 src_ip=10.0.0.1 action=deny',

    "CSV": """timestamp,src_ip,action
2026-02-14,10.0.0.1,deny""",

    "XML": '<event><host>firewall01</host></event>',

    "TEXT": 'Login failed for user jsmith',
}

for name, raw in tests.items():
    result = detect_format(raw)
    print(f"{name:8} -> {result}")
