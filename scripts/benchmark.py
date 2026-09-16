"""Offline ULPF throughput benchmark. No network calls."""
from __future__ import annotations
import argparse,time,statistics,json,sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ulpf.pipeline import Pipeline
from ulpf.config import load_pipeline_config,load_parser_specs
from ulpf.registry import ParserRegistry
from ulpf.enricher import build_enrichers

SAMPLE='date=2026-09-09 time=18:10:32 devname="FW-01" type=traffic srcip=192.168.1.25 srcport=51542 dstip=8.8.8.8 dstport=443 proto=6 action="accept" service="HTTPS"'

def main():
 p=argparse.ArgumentParser();p.add_argument('-n','--events',type=int,default=10000);a=p.parse_args()
 cfg=load_pipeline_config(); specs=load_parser_specs(cfg); pipe=Pipeline(cfg,registry=ParserRegistry(specs),enrichers=build_enrichers(cfg))
 start=time.perf_counter(); lat=[]
 for _ in range(a.events):
  t=time.perf_counter(); pipe.process_raw(SAMPLE,{'source_type':'benchmark','address':'local'}); lat.append((time.perf_counter()-t)*1000)
 elapsed=time.perf_counter()-start
 result={'events':a.events,'elapsed_seconds':round(elapsed,4),'events_per_second':round(a.events/elapsed,2),'avg_latency_ms':round(statistics.mean(lat),4),'p95_latency_ms':round(sorted(lat)[int(len(lat)*.95)-1],4),'offline':True,'network_calls':0}
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
