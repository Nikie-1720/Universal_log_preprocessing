"""Ingestion sources: syslog (UDP/TCP), file tailing, directory watch, stdin."""
from __future__ import annotations

import json
import os
import queue
import socket
import ssl
import threading
import time
from abc import ABC, abstractmethod

from ulpf.utils import ensure_dir, now_iso


class Source(ABC):
    """A receiver pushes (raw, source_meta) tuples into the pipeline queue."""

    def __init__(self, cfg: dict, out_queue: queue.Queue, stats):
        self.cfg = cfg
        self.q = out_queue
        self.stats = stats
        self.stop_event = threading.Event()

    @abstractmethod
    def start(self) -> None: ...

    def stop(self) -> None:
        self.stop_event.set()

    def _enqueue(self, raw: str, meta: dict) -> None:
        if not raw.strip():
            return
        meta.setdefault("received_time", now_iso())
        try:
            self.q.put_nowait((raw, meta))
            self.stats.inc("queued")
        except queue.Full:
            self.stats.inc("queue_dropped")


class SyslogSource(Source):
    """Concurrent RFC3164/RFC5424 receiver over UDP and TCP (optional TLS)."""

    def __init__(self, cfg: dict, out_queue: queue.Queue, stats):
        super().__init__(cfg, out_queue, stats)
        self.host = cfg.get("host", "0.0.0.0")
        self.udp_port = int(cfg.get("udp_port", 0) or 0)
        self.tcp_port = int(cfg.get("tcp_port", 0) or 0)
        self.tls_cert = cfg.get("tls_cert")
        self.tls_key = cfg.get("tls_key")
        self._socks = []

    def start(self) -> None:
        if self.udp_port:
            threading.Thread(target=self._udp_loop, daemon=True,
                             name=f"ulpf-udp-{self.udp_port}").start()
        if self.tcp_port:
            threading.Thread(target=self._tcp_accept_loop, daemon=True,
                             name=f"ulpf-tcp-{self.tcp_port}").start()

    def _udp_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        try:
            sock.bind((self.host, self.udp_port))
        except OSError as exc:
            sock.close()
            print(
                f"[ULPF] UDP syslog listener unavailable on "
                f"{self.host}:{self.udp_port}: {exc}"
            )
            return
        self._socks.append(sock)
        sock.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for line in data.decode("utf-8", errors="replace").splitlines():
                self._enqueue(line, {"source_type": "syslog", "address": addr[0],
                                     "transport": "udp"})

    def _tcp_accept_loop(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.host, self.tcp_port))
        except OSError as exc:
            server.close()
            print(
                f"[ULPF] TCP syslog listener unavailable on "
                f"{self.host}:{self.tcp_port}: {exc}"
            )
            return
        server.listen(64)
        self._socks.append(server)
        server.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.tls_cert and self.tls_key:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.tls_cert, self.tls_key)
                conn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=self._tcp_client, args=(conn, addr), daemon=True).start()

    def _tcp_client(self, conn: socket.socket, addr) -> None:
        transport = "tls" if self.tls_cert else "tcp"
        buffer = b""
        try:
            conn.settimeout(30)
            while not self.stop_event.is_set():
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buffer += chunk
                # Octet-counted framing: "<N> " -> read exactly N bytes
                if buffer[:1].isdigit():
                    m = buffer.find(b" ")
                    if m > 0:
                        try:
                            need = int(buffer[1:m])
                        except ValueError:
                            need = 0
                        if need and len(buffer) >= m + 1 + need:
                            payload = buffer[m + 1:m + 1 + need].decode("utf-8", errors="replace")
                            buffer = buffer[m + 1 + need:]
                            self._enqueue(payload, {"source_type": "syslog",
                                                    "address": addr[0], "transport": transport})
                            continue
                while b"\n" in buffer:
                    line, _, buffer = buffer.partition(b"\n")
                    self._enqueue(line.rstrip(b"\r").decode("utf-8", errors="replace"),
                                  {"source_type": "syslog", "address": addr[0],
                                   "transport": transport})
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        super().stop()
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass


class FileTailSource(Source):
    """Tail one or more files with persisted offsets (survives restarts)."""

    def __init__(self, cfg: dict, out_queue: queue.Queue, stats):
        super().__init__(cfg, out_queue, stats)
        paths = cfg.get("path")
        self.paths = [paths] if isinstance(paths, str) else list(paths or [])
        self.follow = bool(cfg.get("follow", True))
        self.read_existing = bool(cfg.get("read_existing", True))
        self.poll_interval = float(cfg.get("poll_interval", 0.5))
        self.state_file = cfg.get("state_file", "data/.ulpf-tail-state.json")
        self.offsets = {}
        self._buffers = {}

    def _load_state(self) -> None:
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                self.offsets = json.load(fh)
        except (OSError, ValueError):
            self.offsets = {}

    def _save_state(self) -> None:
        try:
            ensure_dir(os.path.dirname(os.path.abspath(self.state_file)) or ".")
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(self.offsets, fh)
        except OSError:
            pass

    def start(self) -> None:
        self._load_state()
        threading.Thread(target=self._loop, daemon=True, name="ulpf-file-tail").start()

    def _read_new(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        offset = self.offsets.get(path, 0)
        if size < offset:  # rotated/truncated
            offset = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                data = fh.read()
                new_offset = fh.tell()
        except OSError:
            return
        buffer = self._buffers.get(path, "") + data
        lines = buffer.split("\n")
        self._buffers[path] = lines.pop()  # keep incomplete tail line
        for line in lines:
            line = line.rstrip("\r")
            if line.strip():
                self._enqueue(line, {"source_type": "file", "address": path,
                                     "transport": "file", "offset": offset})
        self.offsets[path] = new_offset

    def _loop(self) -> None:
        for path in self.paths:
            if not self.read_existing and path not in self.offsets:
                try:
                    self.offsets[path] = os.path.getsize(path)
                except OSError:
                    self.offsets[path] = 0
        last_save = 0.0
        while not self.stop_event.is_set():
            for path in self.paths:
                self._read_new(path)
            if time.time() - last_save > 5:
                self._save_state()
                last_save = time.time()
            if not self.follow:
                for path in self.paths:
                    self._flush_buffer(path)
                self._save_state()
                return
            time.sleep(self.poll_interval)

    def _flush_buffer(self, path: str) -> None:
        buffer = self._buffers.pop(path, "")
        if buffer.strip():
            self._enqueue(buffer, {"source_type": "file", "address": path, "transport": "file"})

    def stop(self) -> None:
        super().stop()
        self._save_state()


class DirectorySource(FileTailSource):
    """Watch a directory for new *.log files and tail each one."""

    def __init__(self, cfg: dict, out_queue: queue.Queue, stats):
        super().__init__(cfg, out_queue, stats)
        self.dir_path = cfg["path"]
        self.pattern = cfg.get("pattern", "*.log")

    def _discover(self):
        import glob
        return sorted(glob.glob(os.path.join(self.dir_path, self.pattern)))

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            for path in self._discover():
                if path not in self.offsets:
                    self.offsets[path] = 0 if self.read_existing else (
                        os.path.getsize(path) if os.path.exists(path) else 0)
                self._read_new(path)
            if not self.follow:
                return
            time.sleep(self.poll_interval)


class StdinSource(Source):
    """Read newline-delimited records from stdin (pipes, redirects)."""

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="ulpf-stdin").start()

    def _loop(self) -> None:
        import sys
        for line in sys.stdin:
            if self.stop_event.is_set():
                return
            self._enqueue(line.rstrip("\r\n"), {"source_type": "stdin", "address": "stdin",
                                                "transport": "stdin"})


def build_sources(input_cfgs: list[dict], out_queue: queue.Queue, stats) -> list[Source]:
    registry = {"syslog": SyslogSource, "file": FileTailSource,
                "dir": DirectorySource, "stdin": StdinSource}
    sources = []
    for cfg in input_cfgs or []:
        cls = registry.get(cfg.get("type"))
        if cls is None:
            raise ValueError(f"unknown input type: {cfg.get('type')}")
        sources.append(cls(cfg, out_queue, stats))
    return sources
