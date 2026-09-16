"""ULPF Collector Agent - offline/local telemetry collector.

The agent is deliberately lightweight and dependency-free:
- tails configured log files/directories on Linux/Unix
- optionally reads systemd journal through journalctl
- optionally reads Windows Event Log through PowerShell/Get-WinEvent
- persists collected records in a local SQLite spool before delivery
- sends batches to the local ULPF gateway over HTTP(S)
- registers and heartbeats with the gateway

No cloud service is used or required.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import platform
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from pathlib import Path


# ============================================================
# DISCOVERY IMPORT
# ============================================================

try:
    # Package execution:
    # python -m agent.agent
    from .discovery import discover

except ImportError:
    # Direct script execution:
    # python agent\agent.py

    AGENT_DIR = Path(__file__).resolve().parent

    if str(AGENT_DIR) not in sys.path:
        sys.path.insert(0, str(AGENT_DIR))

    from discovery import discover


# ============================================================
# PATHS / DEFAULTS
# ============================================================

ROOT = Path(__file__).resolve().parent

DEFAULT_CONFIG = ROOT / "agent.yaml"
DEFAULT_STATE = ROOT / "state"

CONFIG = os.environ.get(
    "ULPF_AGENT_CONFIG",
    str(DEFAULT_CONFIG)
)


# ============================================================
# UTILITIES
# ============================================================

def now_iso():
    """Return current UTC timestamp."""

    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime()
    )


def safe_int(value, default=0):
    """Convert a value to int without crashing the agent."""

    try:
        return int(value)

    except (TypeError, ValueError):
        return default


def safe_float(value, default=1.0):
    """Convert a value to float without crashing the agent."""

    try:
        return float(value)

    except (TypeError, ValueError):
        return default


# ============================================================
# CONFIG LOADER
# ============================================================

def load_config(path):
    """
    Load agent configuration.

    JSON is accepted even with .yaml extension to keep the
    agent zero-dependency.

    A tiny YAML subset is also supported:
        key: value

        list:
          - item1
          - item2
    """

    try:
        text = Path(path).read_text(
            encoding="utf-8"
        )

        # ----------------------------------------------------
        # First try JSON
        # ----------------------------------------------------

        try:
            return json.loads(text)

        except json.JSONDecodeError:
            pass

        # ----------------------------------------------------
        # Tiny YAML subset
        # ----------------------------------------------------

        out = {}
        current = None

        for raw in text.splitlines():

            s = raw.strip()

            if not s:
                continue

            if s.startswith("#"):
                continue

            # YAML list item
            if s.startswith("- ") and current:
                out.setdefault(current, []).append(
                    s[2:].strip().strip("\"'")
                )
                continue

            # key:value
            if ":" in s:

                k, v = s.split(":", 1)

                k = k.strip()
                v = v.strip()

                # Empty value -> start list
                if not v:

                    current = k
                    out[k] = []

                else:

                    current = None

                    if v.lower() in ("true", "false"):

                        v = (
                            v.lower() == "true"
                        )

                    elif v.isdigit():

                        v = int(v)

                    else:

                        v = v.strip("\"'")

                    out[k] = v

        return out

    except OSError as e:

        raise SystemExit(
            f"Cannot read agent config: {e}"
        )


# ============================================================
# SQLITE SPOOL
# ============================================================

class Spool:

    def __init__(self, path):

        Path(path).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.db = sqlite3.connect(
            path,
            check_same_thread=False
        )

        self.lock = threading.Lock()

        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                created REAL NOT NULL,
                fingerprint TEXT UNIQUE
            )
            """
        )

        self.max_spool = safe_int(
            os.environ.get(
                "ULPF_AGENT_MAX_SPOOL",
                "100000"
            ),
            100000
        )

        self.db.execute(
            "PRAGMA journal_mode=WAL"
        )

        self.db.execute(
            "PRAGMA synchronous=FULL"
        )

        self.db.commit()

    # --------------------------------------------------------
    # PUT
    # --------------------------------------------------------

    def put(self, payload):

        with self.lock:

            blob = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":")
            )

            identity = payload.get(
                "offset"
            )

            # Windows Event Log deduplication
            if identity is None:

                try:

                    raw = str(
                        payload.get("raw", "")
                    )

                    obj = json.loads(raw)

                    identity = (
                        obj.get("Id")
                        or
                        obj.get("RecordId")
                    )

                except Exception:

                    identity = None

            fingerprint_source = (
                str(payload.get("agent_id", ""))
                + "|"
                + str(payload.get("address", ""))
                + "|"
                + str(
                    identity
                    if identity is not None
                    else payload.get("raw", "")
                )
            )

            fp = hashlib.sha256(
                fingerprint_source.encode(
                    "utf-8"
                )
            ).hexdigest()

            count = self.db.execute(
                "SELECT COUNT(*) FROM queue"
            ).fetchone()[0]

            # ------------------------------------------------
            # Protect disk from unlimited growth
            # ------------------------------------------------

            if count >= self.max_spool:

                delete_count = max(
                    1,
                    count - self.max_spool + 1
                )

                self.db.execute(
                    """
                    DELETE FROM queue
                    WHERE id IN (
                        SELECT id
                        FROM queue
                        ORDER BY id
                        LIMIT ?
                    )
                    """,
                    (delete_count,)
                )

            self.db.execute(
                """
                INSERT OR IGNORE INTO queue
                (
                    payload,
                    created,
                    fingerprint
                )
                VALUES (?, ?, ?)
                """,
                (
                    blob,
                    time.time(),
                    fp
                )
            )

            self.db.commit()

    # --------------------------------------------------------
    # BATCH
    # --------------------------------------------------------

    def batch(self, n):

        n = max(
            1,
            safe_int(n, 100)
        )

        with self.lock:

            rows = self.db.execute(
                """
                SELECT id, payload
                FROM queue
                ORDER BY id
                LIMIT ?
                """,
                (n,)
            ).fetchall()

        return [
            (
                row_id,
                json.loads(payload)
            )
            for row_id, payload in rows
        ]

    # --------------------------------------------------------
    # ACK
    # --------------------------------------------------------

    def ack(self, ids):

        if not ids:
            return

        with self.lock:

            self.db.executemany(
                "DELETE FROM queue WHERE id=?",
                [
                    (i,)
                    for i in ids
                ]
            )

            self.db.commit()

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    def size(self):

        with self.lock:

            return self.db.execute(
                "SELECT COUNT(*) FROM queue"
            ).fetchone()[0]

    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

    def close(self):

        self.db.close()

    # --------------------------------------------------------
    # INTEGRITY
    # --------------------------------------------------------

    def integrity_check(self):

        with self.lock:

            return (
                self.db.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0]
                == "ok"
            )


# ============================================================
# ULPF AGENT
# ============================================================

class Agent:

    def __init__(self, cfg):

        self.cfg = cfg

        # ----------------------------------------------------
        # Persistent Agent ID
        # ----------------------------------------------------

        self.id_file = Path(
            cfg.get(
                "agent_id_file",
                DEFAULT_STATE / "agent-id"
            )
        )

        self.id_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        if self.id_file.exists():

            self.agent_id = (
                self.id_file.read_text(
                    encoding="utf-8"
                ).strip()
            )

        else:

            self.agent_id = (
                "ULPF-"
                + str(uuid.uuid4())
            )

            self.id_file.write_text(
                self.agent_id,
                encoding="utf-8"
            )

        # ----------------------------------------------------
        # Agent name
        # ----------------------------------------------------

        self.name = (
            cfg.get("name")
            or platform.node()
            or self.agent_id
        )

        # ----------------------------------------------------
        # Gateway
        # ----------------------------------------------------

        self.gateway = str(
            cfg.get(
                "gateway",
                "http://127.0.0.1:5173"
            )
        ).rstrip("/")

        # ----------------------------------------------------
        # Token
        # ----------------------------------------------------

        self.token = os.environ.get(
            "ULPF_AGENT_TOKEN",
            str(cfg.get("token", ""))
        )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        self.tls = cfg.get("tls") or {}

        self.ssl_context = (
            self._ssl_context()
        )

        # ----------------------------------------------------
        # SQLite spool
        # ----------------------------------------------------

        self.spool = Spool(
            cfg.get(
                "spool",
                str(
                    DEFAULT_STATE
                    / "spool.db"
                )
            )
        )

        # ----------------------------------------------------
        # Stop event
        # ----------------------------------------------------

        self.stop = threading.Event()

        # ----------------------------------------------------
        # Local discovery
        # ----------------------------------------------------

        self.discovery = discover(
            cfg.get("files", [])
        )

        # ----------------------------------------------------
        # File offsets
        # ----------------------------------------------------

        self.offsets = {}

        self.offset_file = Path(
            cfg.get(
                "offset_file",
                str(
                    DEFAULT_STATE
                    / "offsets.json"
                )
            )
        )

        self.offset_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        try:

            loaded = json.loads(
                self.offset_file.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(loaded, dict):

                self.offsets = loaded

        except Exception:

            self.offsets = {}

    # ========================================================
    # TLS
    # ========================================================

    def _ssl_context(self):
        """
        Build optional TLS/mTLS context.

        Certificate verification remains enabled by default.
        """

        if not self.gateway.lower().startswith(
            "https://"
        ):
            return None

        ca_file = (
            self.tls.get("ca_file")
        )

        if ca_file:

            ctx = ssl.create_default_context(
                cafile=ca_file
            )

        else:

            ctx = ssl.create_default_context()

        # ----------------------------------------------------
        # Client certificate for mTLS
        # ----------------------------------------------------

        cert_file = self.tls.get(
            "cert_file"
        )

        key_file = self.tls.get(
            "key_file"
        )

        if cert_file and key_file:

            ctx.load_cert_chain(
                cert_file,
                key_file
            )

        # ----------------------------------------------------
        # Explicit development-only bypass
        # ----------------------------------------------------

        if (
            self.tls.get(
                "insecure_skip_verify"
            )
            is True
        ):

            ctx.check_hostname = False
            ctx.verify_mode = (
                ssl.CERT_NONE
            )

        return ctx

    # ========================================================
    # HTTP HEADERS
    # ========================================================

    def headers(self):

        headers = {
            "Content-Type":
                "application/json",

            "X-ULPF-Agent-ID":
                self.agent_id
        }

        if self.token:

            headers["Authorization"] = (
                "Bearer "
                + self.token
            )

        return headers

    # ========================================================
    # POST
    # ========================================================

    def post(
        self,
        path,
        payload,
        timeout=8
    ):

        data = json.dumps(
            payload,
            ensure_ascii=False
        ).encode("utf-8")

        request = urllib.request.Request(
            self.gateway + path,
            data=data,
            headers=self.headers(),
            method="POST"
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=self.ssl_context
        ) as response:

            body = response.read()

            if not body:

                return {}

            return json.loads(body)

    # ========================================================
    # REGISTER
    # ========================================================

    def register(self):

        try:

            result = self.post(
                "/api/agents/register",
                {
                    "agent_id":
                        self.agent_id,

                    "name":
                        self.name,

                    "hostname":
                        platform.node(),

                    "os":
                        platform.platform(),

                    "agent_version":
                        "1.0.0",

                    "sources":
                        self.discovery.get(
                            "sources",
                            []
                        ),

                    "capabilities":
                        self.discovery.get(
                            "capabilities",
                            []
                        ),

                    "discovery":
                        self.discovery,
                }
            )

            print(
                "agent registered:",
                self.agent_id
            )

            return result

        except Exception as e:

            print(
                "register offline:",
                e,
                file=sys.stderr
            )

            return None

    # ========================================================
    # HEARTBEAT
    # ========================================================

    def heartbeat(self):

        payload = {
            "agent_id":
                self.agent_id,

            "hostname":
                platform.node(),

            "os":
                platform.system(),

            "queue_size":
                self.spool.size(),

            "time":
                now_iso()
        }

        try:

            return self.post(
                "/api/agents/heartbeat",
                payload
            )

        except urllib.error.HTTPError as e:

            # ------------------------------------------------
            # Gateway lost agent registry
            # ------------------------------------------------

            if e.code == 404:

                print(
                    "heartbeat: agent not registered; "
                    "attempting re-registration...",
                    file=sys.stderr
                )

                result = self.register()

                if result:

                    print(
                        "agent re-registered successfully",
                        file=sys.stderr
                    )

                    return result

            return None

        except Exception:

            return None

    # ========================================================
    # ENQUEUE
    # ========================================================

    def enqueue(
        self,
        raw,
        source,
        address,
        offset=None
    ):

        if not raw or not raw.strip():

            return

        payload = {
            "raw":
                raw,

            "source_type":
                source,

            "address":
                address,

            "transport":
                "agent",

            "agent_id":
                self.agent_id,

            "agent_name":
                self.name,

            "received_time":
                now_iso()
        }

        if offset is not None:

            payload["offset"] = offset

        self.spool.put(
            payload
        )

    # ========================================================
    # SAVE OFFSETS
    # ========================================================

    def save_offsets(self):

        self.offset_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        tmp = self.offset_file.with_suffix(
            ".tmp"
        )

        tmp.write_text(
            json.dumps(
                self.offsets,
                indent=2,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        tmp.replace(
            self.offset_file
        )

    # ========================================================
    # TAIL FILE
    # ========================================================

    def tail_file(self, path):
        """
        Read only new content from a log file.

        IMPORTANT:
        Do NOT use:

            for line in f:
                f.tell()

        because Python can raise:

            OSError: telling position disabled by next() call

        We therefore use readline() and call tell() immediately
        after each successful readline().
        """

        # ----------------------------------------------------
        # Check file size
        # ----------------------------------------------------

        try:

            size = os.path.getsize(
                path
            )

        except OSError:

            return

        # ----------------------------------------------------
        # Stable absolute path key
        # ----------------------------------------------------

        key = os.path.abspath(
            path
        )

        # ----------------------------------------------------
        # Read previous offset safely
        # ----------------------------------------------------

        off = safe_int(
            self.offsets.get(
                key,
                0
            ),
            0
        )

        # ----------------------------------------------------
        # File was truncated/rotated
        # ----------------------------------------------------

        if size < off:

            off = 0

        # ----------------------------------------------------
        # Read from saved offset
        # ----------------------------------------------------

        try:

            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                f.seek(off)

                while True:

                    # ----------------------------------------
                    # IMPORTANT:
                    # readline() instead of iterator
                    # ----------------------------------------

                    line = f.readline()

                    if not line:

                        break

                    # ----------------------------------------
                    # tell() is safe here
                    # ----------------------------------------

                    new_offset = f.tell()

                    clean_line = line.rstrip(
                        "\r\n"
                    )

                    if clean_line.strip():

                        self.enqueue(
                            clean_line,
                            "file",
                            path,
                            new_offset
                        )

                    # ----------------------------------------
                    # Persist offset in memory
                    # ----------------------------------------

                    self.offsets[key] = (
                        new_offset
                    )

        except (
            OSError,
            UnicodeError
        ):

            return

    # ========================================================
    # DISCOVER FILES
    # ========================================================

    def discover_files(self):

        result = []

        # ----------------------------------------------------
        # Explicit files
        # ----------------------------------------------------

        for item in (
            self.cfg.get(
                "files",
                []
            )
            or []
        ):

            p = Path(
                os.path.expandvars(
                    str(item)
                )
            )

            if p.is_file():

                result.append(
                    str(p)
                )

        # ----------------------------------------------------
        # Directories
        # ----------------------------------------------------

        for d in (
            self.cfg.get(
                "directories",
                []
            )
            or []
        ):

            if isinstance(d, dict):

                directory_path = d.get(
                    "path"
                )

                pattern = d.get(
                    "pattern",
                    "*.log"
                )

            else:

                directory_path = d
                pattern = "*.log"

            if not directory_path:

                continue

            p = Path(
                os.path.expandvars(
                    str(directory_path)
                )
            )

            if not p.exists():

                continue

            try:

                for x in p.rglob("*"):

                    if (
                        x.is_file()
                        and
                        fnmatch.fnmatch(
                            x.name,
                            pattern
                        )
                    ):

                        result.append(
                            str(x)
                        )

            except OSError:

                continue

        # ----------------------------------------------------
        # Remove duplicates
        # ----------------------------------------------------

        return list(
            dict.fromkeys(result)
        )

    # ========================================================
    # FILE COLLECTION LOOP
    # ========================================================

    def file_loop(self):

        while not self.stop.is_set():

            try:

                files = self.discover_files()

                for path in files:

                    self.tail_file(path)

                # --------------------------------------------
                # Persist offsets after every scan
                # --------------------------------------------

                self.save_offsets()

            except Exception as e:

                print(
                    "file_loop error:",
                    e,
                    file=sys.stderr
                )

            interval = safe_float(
                self.cfg.get(
                    "poll_interval",
                    1.0
                ),
                1.0
            )

            self.stop.wait(
                max(0.1, interval)
            )

    # ========================================================
    # JOURNALD
    # ========================================================

    def journal_loop(self):

        if (
            platform.system()
            == "Windows"
        ):

            return

        if not self.cfg.get(
            "journald",
            False
        ):

            return

        cursor_key = (
            "__journald_cursor__"
        )

        cursor = str(
            self.offsets.get(
                cursor_key,
                ""
            )
            or ""
        )

        cmd = [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "json",
            "--show-cursor"
        ]

        if cursor:

            cmd.extend(
                [
                    "--after-cursor",
                    cursor
                ]
            )

        try:

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )

        except (
            OSError,
            FileNotFoundError
        ):

            return

        while not self.stop.is_set():

            line = (
                proc.stdout.readline()
                if proc.stdout
                else ""
            )

            if not line:

                time.sleep(0.2)
                continue

            line = line.rstrip(
                "\r\n"
            )

            if not line:

                continue

            # ------------------------------------------------
            # Cursor
            # ------------------------------------------------

            if line.startswith(
                "-- cursor:"
            ):

                self.offsets[
                    cursor_key
                ] = line.split(
                    ":",
                    1
                )[1].strip()

                self.save_offsets()

                continue

            # ------------------------------------------------
            # JSON
            # ------------------------------------------------

            try:

                obj = json.loads(
                    line
                )

            except json.JSONDecodeError:

                continue

            raw = obj.get(
                "MESSAGE"
            )

            if raw is None:

                raw = line

            self.enqueue(
                str(raw),
                "journald",
                "systemd-journal"
            )

        try:

            proc.terminate()

        except OSError:

            pass

    # ========================================================
    # WINDOWS EVENT LOG
    # ========================================================

    def windows_loop(self):

        if (
            platform.system()
            != "Windows"
        ):

            return

        if not self.cfg.get(
            "windows_eventlog",
            False
        ):

            return

        channels = self.cfg.get(
            "windows_channels",
            [
                "System",
                "Application",
                "Security"
            ]
        )

        while not self.stop.is_set():

            for ch in channels:

                ps = (
                    "Get-WinEvent "
                    "-LogName '"
                    + str(ch).replace(
                        "'",
                        "''"
                    )
                    + "' "
                    "-MaxEvents 20 | "
                    "ForEach-Object { "
                    "$_ | "
                    "ConvertTo-Json "
                    "-Compress "
                    "-Depth 5 }"
                )

                try:

                    out = (
                        subprocess.check_output(
                            [
                                "powershell",
                                "-NoProfile",
                                "-NonInteractive",
                                "-Command",
                                ps
                            ],
                            stderr=subprocess.DEVNULL,
                            text=True,
                            timeout=15
                        )
                    )

                    for line in out.splitlines():

                        if line.strip():

                            self.enqueue(
                                line,
                                "windows-eventlog",
                                ch
                            )

                except Exception:

                    pass

            interval = safe_float(
                self.cfg.get(
                    "windows_poll_interval",
                    5
                ),
                5
            )

            self.stop.wait(
                max(1, interval)
            )

    # ========================================================
    # SEND LOOP
    # ========================================================

    def send_loop(self):

        interval = safe_float(
            self.cfg.get(
                "send_interval",
                0.5
            ),
            0.5
        )

        batch_size = safe_int(
            self.cfg.get(
                "batch_size",
                100
            ),
            100
        )

        backoff = interval

        while not self.stop.is_set():

            rows = self.spool.batch(
                batch_size
            )

            # ------------------------------------------------
            # Nothing to send
            # ------------------------------------------------

            if not rows:

                self.stop.wait(
                    max(0.1, interval)
                )

                continue

            ids = [
                row_id
                for row_id, _
                in rows
            ]

            try:

                batch_payload = []

                for row_id, item in rows:

                    copy = dict(
                        item
                    )

                    copy[
                        "_spool_id"
                    ] = row_id

                    batch_payload.append(
                        copy
                    )

                response = self.post(
                    "/api/ingest-agent",
                    {
                        "agent_id":
                            self.agent_id,

                        "events":
                            batch_payload
                    },
                    timeout=15
                )

                ack_ids = response.get(
                    "ack_ids"
                )

                # ------------------------------------------------
                # Explicit acknowledgements
                # ------------------------------------------------

                if isinstance(
                    ack_ids,
                    list
                ):

                    valid_ids = []

                    for item in ack_ids:

                        try:

                            valid_ids.append(
                                int(item)
                            )

                        except (
                            TypeError,
                            ValueError
                        ):

                            continue

                    self.spool.ack(
                        valid_ids
                    )

                # ------------------------------------------------
                # Backward-compatible accepted count
                # ------------------------------------------------

                elif safe_int(
                    response.get(
                        "accepted",
                        0
                    ),
                    0
                ) >= len(rows):

                    self.spool.ack(
                        ids
                    )

                # ------------------------------------------------
                # Successful send
                # ------------------------------------------------

                backoff = interval

            except Exception as e:

                print(
                    "send_loop offline:",
                    e,
                    file=sys.stderr
                )

                self.stop.wait(
                    max(0.1, backoff)
                )

                backoff = min(
                    30.0,
                    max(
                        interval,
                        backoff * 2
                    )
                )

    # ========================================================
    # HEARTBEAT LOOP
    # ========================================================

    def heartbeat_loop(self):

        while not self.stop.is_set():

            self.heartbeat()

            interval = safe_float(
                self.cfg.get(
                    "heartbeat_interval",
                    10
                ),
                10
            )

            self.stop.wait(
                max(1, interval)
            )

    # ========================================================
    # DIAGNOSTICS
    # ========================================================

    def diagnostics(self):
        """
        Print local-only discovery/capability report.

        No gateway/network access is performed.
        """

        print(
            json.dumps(
                self.discovery,
                indent=2,
                ensure_ascii=False
            )
        )

    # ========================================================
    # RUN
    # ========================================================

    def run(self):

        print(
            "Starting ULPF Collector Agent..."
        )

        print(
            "Agent ID:",
            self.agent_id
        )

        print(
            "Gateway:",
            self.gateway
        )

        # ----------------------------------------------------
        # Registration
        # ----------------------------------------------------

        self.register()

        # ----------------------------------------------------
        # Worker threads
        # ----------------------------------------------------

        threads = [

            threading.Thread(
                target=self.file_loop,
                name="ULPF-FileCollector",
                daemon=True
            ),

            threading.Thread(
                target=self.journal_loop,
                name="ULPF-JournaldCollector",
                daemon=True
            ),

            threading.Thread(
                target=self.windows_loop,
                name="ULPF-WindowsEventCollector",
                daemon=True
            ),

            threading.Thread(
                target=self.send_loop,
                name="ULPF-Sender",
                daemon=True
            ),

            threading.Thread(
                target=self.heartbeat_loop,
                name="ULPF-Heartbeat",
                daemon=True
            )
        ]

        # ----------------------------------------------------
        # Start workers
        # ----------------------------------------------------

        for thread in threads:

            thread.start()

            print(
                "Started:",
                thread.name
            )

        # ----------------------------------------------------
        # Keep main agent alive
        # ----------------------------------------------------

        try:

            while not self.stop.is_set():

                time.sleep(1)

        except KeyboardInterrupt:

            print(
                "\nStopping ULPF Agent..."
            )

            self.stop.set()

        finally:

            # ------------------------------------------------
            # Save offsets
            # ------------------------------------------------

            try:

                self.save_offsets()

            except Exception:

                pass

            # ------------------------------------------------
            # Close spool
            # ------------------------------------------------

            try:

                self.spool.close()

            except Exception:

                pass

            print(
                "ULPF Agent stopped."
            )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=
            "ULPF offline collector agent"
    )

    parser.add_argument(
        "--config",
        default=CONFIG,
        help="Path to agent configuration"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "run",
            "discover"
        ],
        default="run"
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Load configuration
    # --------------------------------------------------------

    cfg = load_config(
        args.config
    )

    # --------------------------------------------------------
    # Create agent
    # --------------------------------------------------------

    agent = Agent(
        cfg
    )

    # --------------------------------------------------------
    # Discovery-only mode
    # --------------------------------------------------------

    if args.command == "discover":

        try:

            agent.diagnostics()

        finally:

            agent.spool.close()

        return 0

    # --------------------------------------------------------
    # Normal run
    # --------------------------------------------------------

    agent.run()

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )