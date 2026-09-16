"""Offline-first AI-assisted log onboarding.

No network access is performed. The baseline mapper is deterministic and always
available. An optional local Ollama adapter may be enabled explicitly; it talks
only to a user-supplied loopback/private endpoint and never to a cloud API.
"""
from __future__ import annotations
import json, os, re, urllib.request
from typing import Any

ALIASES = {
    "src":"source.ip","srcip":"source.ip","src_ip":"source.ip","source_ip":"source.ip",
    "dst":"destination.ip","dstip":"destination.ip","dst_ip":"destination.ip","destination_ip":"destination.ip",
    "spt":"source.port","srcport":"source.port","src_port":"source.port","source_port":"source.port",
    "dpt":"destination.port","dstport":"destination.port","dst_port":"destination.port","dest_port":"destination.port","destination_port":"destination.port",
    "proto":"network.transport","protocol":"network.transport","transport":"network.transport",
    "act":"event.action","action":"event.action","outcome":"event.outcome","status":"event.outcome",
    "user":"user.name","username":"user.name","user_name":"user.name",
    "devname":"device.host","hostname":"device.host","host":"device.host","device":"device.host",
    "msg":"message","message":"message","service":"destination.service",
    "src_country":"geo.source.country","dst_country":"geo.destination.country",
}

def _pairs(raw: str) -> list[tuple[str,str]]:
    pairs=[]
    for m in re.finditer(r'(?<![\w.-])([A-Za-z_][\w.-]*)\s*=\s*("(?:\\.|[^"\\])*"|\'[^\']*\'|[^\s]+)', raw):
        val=m.group(2).strip('"\'')
        pairs.append((m.group(1), val))
    return pairs

def heuristic_analyze(raw: str) -> dict[str,Any]:
    pairs=_pairs(raw)
    suggestions=[]
    for source, value in pairs:
        target=ALIASES.get(source.lower())
        confidence=0.96 if target else 0.0
        reason="known security-log field alias" if target else "unmapped field; approval required"
        if not target:
            low=source.lower()
            if low.endswith("ip") and "src" in low: target="source.ip"; confidence=.86; reason="name pattern"
            elif low.endswith("ip") and ("dst" in low or "dest" in low): target="destination.ip"; confidence=.86; reason="name pattern"
            elif low.endswith("port") and "src" in low: target="source.port"; confidence=.84; reason="name pattern"
            elif low.endswith("port") and ("dst" in low or "dest" in low): target="destination.port"; confidence=.84; reason="name pattern"
        if target:
            suggestions.append({"source":source,"target":target,"sample":value,"confidence":confidence,"reason":reason})
    return {"engine":"offline-heuristic-v1","mode":"offline-assisted","suggestions":suggestions,
            "unknown_fields":[s for s,v in pairs if not any(x["source"]==s for x in suggestions)],
            "network_access_required":False}

def ollama_analyze(raw: str, endpoint: str, model: str) -> dict[str,Any]:
    """Optional local model call. Refuses non-private endpoints by default."""
    url=endpoint.rstrip('/') + '/api/generate'
    host=url.split('/')[2].split(':')[0].lower()
    allowed=host in {'127.0.0.1','localhost','::1'} or host.startswith('10.') or host.startswith('192.168.') or host.startswith('172.')
    if not allowed: raise ValueError('local AI endpoint must be loopback or RFC1918 private address')
    prompt=("Map fields in this log to ULPF UES paths. Return JSON array with source,target,confidence. "
            "Do not invent fields. Log:\n"+raw[:12000])
    body=json.dumps({'model':model,'prompt':prompt,'stream':False}).encode()
    req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=20) as r: data=json.loads(r.read())
    text=str(data.get('response','')).strip()
    try: parsed=json.loads(text)
    except json.JSONDecodeError:
        m=re.search(r'\[[\s\S]*\]',text); parsed=json.loads(m.group(0)) if m else []
    return {'engine':'local-ollama','mode':'local-model','model':model,'suggestions':parsed if isinstance(parsed,list) else [],'network_access_required':False}

def analyze(raw: str) -> dict[str,Any]:
    result=heuristic_analyze(raw)
    if os.environ.get('ULPF_LOCAL_AI','').lower() in {'1','true','yes'}:
        try:
            local=ollama_analyze(raw, os.environ.get('ULPF_LOCAL_AI_ENDPOINT','http://127.0.0.1:11434'), os.environ.get('ULPF_LOCAL_AI_MODEL','llama3.2:3b'))
            result.update(local)
        except Exception as exc:
            result['local_model_error']=str(exc)
    return result
