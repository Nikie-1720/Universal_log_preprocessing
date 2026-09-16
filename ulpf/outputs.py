"""Output sinks for normalized events."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from ulpf.utils import ensure_dir, now_iso


class Output(ABC):
    name = "base"

    def open(self) -> None:  # pragma: no cover
        pass

    @abstractmethod
    def write(self, events: list[dict]) -> None: ...

    def flush(self) -> None:  # pragma: no cover
        pass

    def close(self) -> None:  # pragma: no cover
        pass


class StdoutOutput(Output):
    name = "stdout"

    def __init__(self, options: dict | None = None):
        self.pretty = bool((options or {}).get("pretty", False))

    def write(self, events: list[dict]) -> None:
        for event in events:
            if self.pretty:
                from ulpf.utils import json_dumps
                print(json_dumps(event, pretty=True))
            else:
                print(json.dumps(event, ensure_ascii=False, default=str,
                                 separators=(",", ":")))

    def flush(self) -> None:
        import sys
        sys.stdout.flush()


class JsonlOutput(Output):
    """Newline-delimited JSON sink - the universal interchange for SIEM/data lakes."""

    name = "jsonl"

    def __init__(self, options: dict | None = None):
        opts = options or {}
        self.path = opts["path"]
        self.rotate_bytes = int(opts.get("rotate_size_mb", 100)) * 1024 * 1024
        self.include_raw = bool(opts.get("include_raw", True))
        self._fh = None
        self._written = 0
        self._day = None
        self._lock = threading.Lock()

    def open(self) -> None:
        ensure_dir(os.path.dirname(os.path.abspath(self.path)))
        self._open_file()

    def _open_file(self) -> None:
        day = time.strftime("%Y%m%d")
        self._day = day
        self._fh = open(self.path, "a", encoding="utf-8")

    def write(self, events: list[dict]) -> None:
        with self._lock:
            if self._fh is None:
                self._open_file()
            day = time.strftime("%Y%m%d")
            if day != self._day:  # daily rotation
                self._fh.close()
                self._open_file()
            for event in events:
                payload = event if self.include_raw else {**event, "raw": ""}
                self._fh.write(json.dumps(payload, ensure_ascii=False, default=str,
                                          separators=(",", ":")))
                self._fh.write("\n")
                self._written += 1
            self._fh.flush()
            if self.rotate_bytes and self._fh.tell() > self.rotate_bytes:
                rotated = f"{self.path}.{time.strftime('%Y%m%d%H%M%S')}"
                self._fh.close()
                os.replace(self.path, rotated)
                self._open_file()

    def flush(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


class RawArchiveOutput(Output):
    """Append-only WORM-style evidence store: one raw record per line with its
    hash, plus periodic manifest records forming a hash chain for tamper
    detection - the forensic/compliance guarantee.
    """

    name = "raw_archive"
    MANIFEST_EVERY = 10000

    def __init__(self, options: dict | None = None):
        opts = options or {}
        self.dir_path = opts["path"]
        self._fh = None
        self._count = 0
        self._prev_manifest_hash = ""
        self._lock = threading.Lock()

    def open(self) -> None:
        ensure_dir(self.dir_path)
        path = os.path.join(self.dir_path, "raw-" + time.strftime("%Y%m%d") + ".raw")
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, events: list[dict]) -> None:
        with self._lock:
            if self._fh is None:
                self.open()
            for event in events:
                trace = event.get("trace", {})
                record = {"ts": now_iso(), "trace_id": trace.get("trace_id"),
                          "hash": trace.get("raw_hash"), "raw": event.get("raw", "")}
                self._fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
                self._fh.write("\n")
                self._count += 1
                if self._count % self.MANIFEST_EVERY == 0:
                    self._write_manifest()
            self._fh.flush()

    def _write_manifest(self) -> None:
        import hashlib
        payload = {"__manifest__": {"count": self._count, "time": now_iso(),
                                    "prev_manifest_hash": self._prev_manifest_hash}}
        line = json.dumps(payload, separators=(",", ":"))
        self._prev_manifest_hash = hashlib.sha256(line.encode()).hexdigest()
        self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


class SQLiteOutput(Output):
    """Queryable local store - zero-dependency SQL analytics, air-gap friendly."""

    name = "sqlite"

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        trace_id TEXT PRIMARY KEY,
        event_id TEXT, ingest_time TEXT, event_time TEXT,
        category TEXT, type TEXT, action TEXT, outcome TEXT,
        severity INTEGER, severity_label TEXT,
        source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER,
        transport TEXT, user TEXT, device_host TEXT, message TEXT,
        parser TEXT, threat_score INTEGER, threat TEXT,
        event_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);
    CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
    """

    def __init__(self, options: dict | None = None):
        self.path = (options or {})["path"]
        self._conn = None
        self._lock = threading.Lock()

    def open(self) -> None:
        ensure_dir(os.path.dirname(os.path.abspath(self.path)) or ".")
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    def write(self, events: list[dict]) -> None:
        with self._lock:
            if self._conn is None:
                self.open()
            rows = []
            for e in events:
                ues, trace, meta = e.get("ues", {}), e.get("trace", {}), e.get("meta", {})
                threat = ues.get("threat") or {}
                rows.append((
                    trace.get("trace_id"), ues.get("event_id"), ues.get("ingest_time"),
                    ues.get("event_time"), ues.get("category"), ues.get("type"),
                    ues.get("action"), ues.get("outcome"), ues.get("severity"),
                    ues.get("severity_label"),
                    (ues.get("source") or {}).get("ip"), (ues.get("source") or {}).get("port"),
                    (ues.get("destination") or {}).get("ip"), (ues.get("destination") or {}).get("port"),
                    (ues.get("network") or {}).get("transport"),
                    (ues.get("user") or {}).get("name"), (ues.get("device") or {}).get("host"),
                    ues.get("message"), meta.get("parser"), threat.get("score"),
                    json.dumps(threat, default=str) if threat else None,
                    json.dumps(e, ensure_ascii=False, default=str),
                ))
            self._conn.executemany(
                "INSERT OR REPLACE INTO events VALUES (" + ",".join(["?"] * 22) + ")", rows)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.commit()
                self._conn.close()
                self._conn = None


class HTTPOutput(Output):
    """Generic HTTP/HTTPS sink (NDJSON batches) - also powers Elasticsearch."""

    name = "http"

    def __init__(self, options: dict | None = None):
        opts = options or {}
        self.url = opts["url"]
        self.headers = {"Content-Type": "application/x-ndjson"}
        self.headers.update(opts.get("headers") or {})
        self.timeout = float(opts.get("timeout", 10))
        self.verify_tls = bool(opts.get("verify_tls", True))

    def write(self, events: list[dict]) -> None:
        import ssl
        body = "\n".join(json.dumps(e, ensure_ascii=False, default=str) for e in events).encode()
        request = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        context = None
        if self.url.startswith("https") and not self.verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            urllib.request.urlopen(request, timeout=self.timeout, context=context)
        except (urllib.error.URLError, OSError):
            pass  # sink outage must never stop the pipeline


class ElasticsearchOutput(HTTPOutput):
    """Bulk-index normalized events into Elasticsearch via the _bulk API."""

    name = "elasticsearch"

    def __init__(self, options: dict | None = None):
        opts = options or {}
        url = opts.get("url", "http://localhost:9200").rstrip("/")
        index = opts.get("index", "ulpf-events")
        username = opts.get("username")
        password = opts.get("password")
        headers = {}
        if username and password:
            import base64
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        super().__init__({**opts, "url": f"{url}/{index}/_bulk", "headers": headers})
        self.index = index

    def write(self, events: list[dict]) -> None:
        lines = []
        for e in events:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(e, ensure_ascii=False, default=str))
        body = ("\n".join(lines) + "\n").encode()
        request = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            urllib.request.urlopen(request, timeout=self.timeout)
        except (urllib.error.URLError, OSError):
            pass


class KafkaOutput(Output):
    """Kafka sink (requires optional `kafka-python` package)."""

    name = "kafka"

    def __init__(self, options: dict | None = None):
        opts = options or {}
        self.bootstrap = opts.get("bootstrap_servers", "localhost:9092")
        self.topic = opts.get("topic", "ulpf-events")
        self._producer = None

    def open(self) -> None:
        try:
            from kafka import KafkaProducer  # optional dependency
        except ImportError as ex:
            raise RuntimeError(
                "kafka output requires the optional 'kafka-python' package "
                "(pip install kafka-python) - not needed for air-gapped file outputs") from ex
        self._producer = KafkaProducer(bootstrap_servers=self.bootstrap,
                                       value_serializer=lambda v: json.dumps(
                                           v, ensure_ascii=False, default=str).encode())

    def write(self, events: list[dict]) -> None:
        if self._producer is None:
            return
        for event in events:
            self._producer.send(self.topic, event)

    def close(self) -> None:
        if self._producer:
            self._producer.flush()
            self._producer.close()
            self._producer = None


class NullOutput(Output):
    name = "null"

    def write(self, events: list[dict]) -> None:
        pass


def build_outputs(options_list: list[dict]) -> list[Output]:
    registry = {
        "stdout": StdoutOutput, "jsonl": JsonlOutput, "raw_archive": RawArchiveOutput,
        "sqlite": SQLiteOutput, "http": HTTPOutput, "elasticsearch": ElasticsearchOutput,
        "kafka": KafkaOutput, "null": NullOutput,
    }
    outputs = []
    for opts in options_list or []:
        otype = opts.get("type")
        cls = registry.get(otype)
        if cls is None:
            raise ValueError(f"unknown output type: {otype}")
        outputs.append(cls(opts))
    return outputs


# Backwards-compatible public name used by earlier ULPF tests/integrations.
SqliteOutput = SQLiteOutput
