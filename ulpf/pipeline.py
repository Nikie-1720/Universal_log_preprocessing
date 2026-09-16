"""Pipeline: processing core + concurrent runtime with batched output."""
from __future__ import annotations

import queue
import signal
import sys
import threading
import time

from ulpf.enricher import build_enrichers
from ulpf.normalizer import Normalizer
from ulpf.registry import ParserRegistry


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self.started_at = time.time()

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + n

    def snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
        elapsed = max(time.time() - self.started_at, 1e-6)
        return {"counters": counters, "elapsed_seconds": round(elapsed, 3),
                "events_per_second": round(counters.get("received", 0) / elapsed, 1)}


class Pipeline:
    """Stateless processing core: raw -> parse -> normalize -> enrich."""

    def __init__(self, config: dict, registry: ParserRegistry | None = None,
                 enrichers: list | None = None):
        self.config = config or {}
        self.registry = registry or ParserRegistry()
        self.enrichers = enrichers if enrichers is not None else build_enrichers(self.config)
        self.normalizer = Normalizer(
            pipeline_id=self.config.get("pipeline_id", "ulpf-core"),
            pipeline_version=str(self.config.get("pipeline_version", "1.0.0")))
        self.stats = Stats()

    def process_raw(self, raw: str, source_meta: dict | None = None) -> dict:
        source_meta = dict(source_meta or {})
        self.stats.inc("received")
        result, parser, spec, det, chained = self.registry.parse_chain(raw)
        try:
            event = self.normalizer.normalize(raw, source_meta, result, parser, spec, det, chained)
        except Exception as ex:  # never lose data
            event = self.normalizer.failure_event(raw, source_meta, det, str(ex))
            self.stats.inc("normalize_failed")
        if event["meta"]["parse_status"] == "parsed":
            self.stats.inc("parsed")
        else:
            self.stats.inc("failed")
        self.stats.inc("parser:" + event["meta"]["parser"])
        if (event["ues"].get("threat") or {}).get("matched"):
            self.stats.inc("threat_hits")
        return event

    def process_many(self, raws) -> list[dict]:
        return [self.process_raw(raw) for raw in raws]


class Runtime:
    """Concurrent pipeline runtime: sources -> queue -> workers -> batched outputs."""

    def __init__(self, config: dict, pipeline: Pipeline | None = None,
                 outputs: list | None = None, sources: list | None = None):
        self.config = config
        pipeline_cfg = config.get("pipeline") or {}
        self.pipeline = pipeline or Pipeline(config)
        self.outputs = outputs
        self.sources = sources
        self._outputs_lazy = outputs is None
        self._sources_lazy = sources is None
        self.queue: queue.Queue = queue.Queue(maxsize=int(pipeline_cfg.get("queue_size", 50000)))
        self.workers_count = int(pipeline_cfg.get("workers", 4))
        self.batch_size = int(pipeline_cfg.get("batch_size", 1000))
        self.flush_interval = float(pipeline_cfg.get("flush_interval", 1.0))
        self.stats_interval = float(pipeline_cfg.get("stats_interval", 10.0))
        self._batch: list[dict] = []
        self._batch_lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._sources_lazy:
            from ulpf.ingestion import build_sources
            self.sources = build_sources(self.config.get("inputs") or [], self.queue,
                                         self.pipeline.stats)
        if self._outputs_lazy:
            from ulpf.outputs import build_outputs
            self.outputs = build_outputs(self.config.get("outputs") or [])
        for out in self.outputs:
            out.open()
        for source in self.sources:
            source.start()
        for i in range(self.workers_count):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f"ulpf-worker-{i}")
            t.start()
            self._threads.append(t)
        self._threads.append(threading.Thread(target=self._batcher_loop, daemon=True,
                                              name="ulpf-batcher"))
        self._threads[-1].start()
        self._threads.append(threading.Thread(target=self._stats_loop, daemon=True,
                                              name="ulpf-stats"))
        self._threads[-1].start()

    def run_forever(self) -> dict:
        def _handle(signum, frame):  # noqa: ARG001
            self._stop.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle)
            except (ValueError, OSError):  # not on main thread / unsupported
                pass
        self.start()
        print(f"ULPF runtime started (pipeline={self.config.get('pipeline_id')} "
              f"workers={self.workers_count}). Press Ctrl+C to stop.", file=sys.stderr)
        try:
            while not self._stop.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            self._stop.set()
        return self.shutdown()

    def shutdown(self) -> dict:
        self._stop.set()
        for source in self.sources or []:
            source.stop()
        deadline = time.time() + 5
        while time.time() < deadline and not self.queue.empty():
            time.sleep(0.1)
        for _ in range(self.workers_count):
            self.queue.put(("__stop__", {}))
        for t in self._threads:
            t.join(timeout=3)
        self._flush_batch()
        stats = self.pipeline.stats.snapshot()
        for out in self.outputs or []:
            out.flush()
            out.close()
        return stats

    # ------------------------------------------------------------ worker path
    def _worker_loop(self) -> None:
        while True:
            try:
                raw, meta = self.queue.get(timeout=0.25)
            except queue.Empty:
                if self._stop.is_set() and self.queue.empty():
                    return
                continue
            if raw == "__stop__":
                self.queue.task_done()
                return
            try:
                event = self.pipeline.process_raw(raw, meta)
                self._append_batch(event)
            finally:
                self.queue.task_done()

    def _append_batch(self, event: dict) -> None:
        flush = False
        with self._batch_lock:
            self._batch.append(event)
            flush = len(self._batch) >= self.batch_size
        if flush:
            self._flush_batch()

    def _flush_batch(self) -> None:
        with self._batch_lock:
            batch, self._batch = self._batch, []
        if not batch or not self.outputs:
            return
        for out in self.outputs:
            try:
                out.write(batch)
                self.pipeline.stats.inc(f"output:{out.name}", len(batch))
            except Exception as ex:
                self.pipeline.stats.inc("output_errors")
                print(f"ULPF: output {out.name} error: {ex}", file=sys.stderr)

    def _batcher_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.flush_interval)
            self._flush_batch()
        self._flush_batch()

    def _stats_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.stats_interval)
            snap = self.pipeline.stats.snapshot()
            counters = snap["counters"]
            print(f"ULPF stats: received={counters.get('received', 0)} "
                  f"parsed={counters.get('parsed', 0)} failed={counters.get('failed', 0)} "
                  f"threats={counters.get('threat_hits', 0)} "
                  f"queue={self.queue.qsize()} rate={snap['events_per_second']}/s",
                  file=sys.stderr)
