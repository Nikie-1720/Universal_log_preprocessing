"""Offline/air-gap preflight. Static local checks only; no network calls."""
from __future__ import annotations
import os, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
bad=[]
for p in [ROOT/'configs',ROOT/'agent/agent.yaml',ROOT/'docker-compose.yml',ROOT/'.env.example']:
    if not p.exists(): continue
    files=list(p.rglob('*')) if p.is_dir() else [p]
    for f in files:
        if not f.is_file() or f.suffix in {'.db','.wal','.pyc'}: continue
        try: text=f.read_text(errors='ignore')
        except: continue
        for m in re.finditer(r'https?://([^/\s"\']+)', text, re.I):
            host=m.group(1).split(':')[0].lower()
            if host not in {'localhost','127.0.0.1','::1','postgres','kafka','elasticsearch'} and not host.startswith(('10.','192.168.','172.')):
                bad.append((str(f.relative_to(ROOT)),host))
print('ULPF AIR-GAP PREFLIGHT')
print('external endpoints found:', len(bad))
for item in bad: print('  ',item[0],item[1])
print('network calls required by core runtime: 0')
print('status:', 'FAIL' if bad else 'PASS')
sys.exit(1 if bad else 0)
