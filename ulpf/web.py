"""
ULPF production-MVP web console + live ingestion + alerting.

LOCAL-FIRST / AIR-GAPPED DESIGN
--------------------------------
- Local JSONL storage is always available.
- PostgreSQL is OPTIONAL.
- PostgreSQL is NEVER required for agent registration.
- PostgreSQL is NEVER initialized unless:
      ULPF_ENABLE_POSTGRES=true
- PostgreSQL failures never block local operation.
- Agent registration/heartbeat/ingestion use local storage first.
- No cloud API is required.

Environment variables
---------------------
ULPF_DATA_DIR
ULPF_CONFIG
ULPF_WEB_HOST
ULPF_WEB_PORT

ULPF_AGENT_TOKEN
ULPF_OPERATOR_TOKEN
ULPF_ALLOW_UNAUTHENTICATED_AGENT

ULPF_ENABLE_POSTGRES=true|false
ULPF_ALERT_WEBHOOK

ULPF_MAX_BODY_BYTES
ULPF_TLS_CERT
ULPF_TLS_KEY
ULPF_TLS_CA
ULPF_TLS_REQUIRE_CLIENT_CERT
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import ssl
import threading
import time
import urllib.error
import urllib.request

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ulpf.config import (
    discover_plugins,
    load_parser_specs,
    load_pipeline_config,
)
from ulpf.plugin_lifecycle import (
    PluginLifecycle,
    PluginLifecycleError,
    PluginNotFoundError,
    InvalidTransitionError,
)
from ulpf.enricher import build_enrichers
from ulpf.ingestion import build_sources
from ulpf.local_ai import analyze as offline_analyze
from ulpf.outputs import build_outputs
from ulpf.pipeline import Pipeline
from ulpf.registry import ParserRegistry
from ulpf.utils import now_iso

try:
    from .correlation.engine import CorrelationEngine
except ImportError:
    from correlation.engine import CorrelationEngine


# ============================================================================
# OPTIONAL POSTGRESQL
# ============================================================================

try:
    from storage.integration import get_repository
except Exception:
    get_repository = None


# ============================================================================
# PATHS / GLOBAL STATE
# ============================================================================

ROOT = Path(__file__).resolve().parent.parent

STATIC = (
    ROOT / "web" / "react-dist"
    if (ROOT / "web" / "react-dist" / "index.html").is_file()
    else ROOT / "web"
)

DATA_DIR = Path(
    os.environ.get(
        "ULPF_DATA_DIR",
        str(ROOT / "data"),
    )
)

EVENT_FILE = DATA_DIR / "web-events.jsonl"
ALERT_FILE = DATA_DIR / "alerts.jsonl"
AGENT_FILE = DATA_DIR / "agents.json"

HOST_LOG_DIRS = [
    Path("/host-logs"),
    Path("/var/log"),
    ROOT / "system-logs",
]


# Main local-state lock.
_lock = threading.RLock()

_events: list[dict] = []
_alerts: list[dict] = []
_agents: dict[str, dict] = {}

_pipeline: Pipeline | None = None

_runtime_queue: queue.Queue | None = None
_runtime_sources = []
_runtime_outputs = []
_runtime_stop = threading.Event()
_runtime_threads: list[threading.Thread] = []

_alert_cooldowns: dict[str, float] = {}
_alert_failed_auth: dict[str, list[float]] = {}

# PostgreSQL state.
_storage_repo = None
_storage_error = None
_storage_attempted = False
_storage_lock = threading.Lock()

_correlation_engine = CorrelationEngine()
_correlations: list[dict] = []


# ============================================================================
# ENVIRONMENT HELPERS
# ============================================================================

def _env_true(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


POSTGRES_ENABLED = _env_true(
    "ULPF_ENABLE_POSTGRES",
    False,
)


# ============================================================================
# LOCAL JSONL STORAGE
# ============================================================================

def _append_jsonl(
    path: Path,
    payload: dict,
) -> None:
    """
    Append JSON to local JSONL storage.

    Local JSONL is the primary storage mechanism for air-gapped mode.
    Failures never crash the HTTP server.
    """

    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open(
            "a",
            encoding="utf-8",
        ) as fh:
            fh.write(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    default=str,
                    separators=(",", ":"),
                )
                + "\n"
            )

    except OSError as ex:
        print(
            "[ULPF] Local JSONL write failed: "
            + repr(ex)
        )


def _load_jsonl(
    path: Path,
    target: list,
    limit: int,
) -> None:
    """
    Load bounded JSONL history.
    """

    if not path.exists():
        return

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as fh:

            for line in fh:

                try:
                    target.append(
                        json.loads(line)
                    )

                except json.JSONDecodeError:
                    continue

        if len(target) > limit:
            del target[:-limit]

    except OSError as ex:
        print(
            "[ULPF] Local JSONL load failed: "
            + repr(ex)
        )


# ============================================================================
# EVENT HELPERS
# ============================================================================

def _get(
    event: dict,
    *paths,
):
    ues = event.get("ues") or {}

    for path in paths:

        cur = ues
        ok = True

        for part in path.split("."):

            if (
                not isinstance(cur, dict)
                or part not in cur
            ):
                ok = False
                break

            cur = cur[part]

        if (
            ok
            and cur not in (
                None,
                "",
            )
        ):
            return cur

    return None


def _event_text(
    event: dict,
) -> str:

    return json.dumps(
        event,
        ensure_ascii=False,
        default=str,
    ).lower()


def _cooldown_key(
    rule: str,
    event: dict,
) -> str:

    src = str(
        _get(
            event,
            "source.ip",
        )
        or "unknown"
    )

    return f"{rule}:{src}"


# ============================================================================
# ALERTS
# ============================================================================

_VISIBLE_ALERT_RULES = {
    "threat-intel-match",
    "high-severity",
    "security-failure",
}


def _alert_is_auth_failure(
    alert: dict,
) -> bool:

    rule = str(
        alert.get("rule")
        or alert.get("rule_id")
        or ""
    )

    if rule not in {
        "security-failure",
        "high-severity",
    }:
        return False

    trace_ids = [
        str(trace_id)
        for trace_id in (
            alert.get("evidence_trace_ids")
            or alert.get("trace_ids")
            or [alert.get("trace_id")]
        )
        if trace_id
    ]

    if not trace_ids:
        return False

    events_by_trace = {
        str(
            (event.get("trace") or {})
            .get("trace_id")
        ): event
        for event in _events
        if (event.get("trace") or {}).get("trace_id")
    }

    linked_events = [
        events_by_trace[trace_id]
        for trace_id in trace_ids
        if trace_id in events_by_trace
    ]

    return (
        bool(linked_events)
        and len(linked_events) == len(trace_ids)
        and all(
            CorrelationEngine._is_auth_failure(
                event
            )
            for event in linked_events
        )
    )


def _group_alerts(
    alerts: list[dict],
) -> list[dict]:

    groups: dict[
        tuple[str, str],
        dict,
    ] = {}

    for alert in alerts:

        if _alert_is_auth_failure(
            alert
        ):
            continue

        rule = str(
            alert.get("rule")
            or alert.get("rule_id")
            or ""
        )

        if (
            rule not in _VISIBLE_ALERT_RULES
            and not rule.startswith(
                "correlation-"
            )
        ):
            continue

        source = str(
            alert.get("source_ip")
            or "unknown"
        )

        key = (
            rule,
            source,
        )

        trace_ids = (
            alert.get("evidence_trace_ids")
            or alert.get("trace_ids")
            or [alert.get("trace_id")]
        )

        trace_ids = [
            str(trace_id)
            for trace_id in trace_ids
            if trace_id
        ]

        current = groups.get(key)

        if current is None:

            current = dict(alert)

            current["alert_ids"] = [
                alert.get("alert_id")
            ]

            current["evidence_trace_ids"] = (
                trace_ids
            )

            current["event_count"] = len(
                trace_ids
            )

            groups[key] = current

            continue

        current["alert_ids"].append(
            alert.get("alert_id")
        )

        current["evidence_trace_ids"] = list(
            dict.fromkeys(
                current[
                    "evidence_trace_ids"
                ]
                + trace_ids
            )
        )

        current["event_count"] = len(
            current[
                "evidence_trace_ids"
            ]
        )

        current["acknowledged"] = (
            current.get(
                "acknowledged",
                False,
            )
            and alert.get(
                "acknowledged",
                False,
            )
        )

        if (
            alert.get(
                "created_at",
                "",
            )
            > current.get(
                "created_at",
                "",
            )
        ):

            current.update({
                "alert_id":
                    alert.get(
                        "alert_id"
                    ),

                "created_at":
                    alert.get(
                        "created_at"
                    ),

                "reason":
                    alert.get(
                        "reason"
                    )
                    or current.get(
                        "reason"
                    ),
            })

    result = list(
        groups.values()
    )

    for alert in result:

        if len(
            alert.get(
                "alert_ids",
                [],
            )
        ) > 1:

            rule = str(
                alert.get("rule")
                or alert.get("rule_id")
            )

            alert["alert_id"] = (
                f"GROUP-{rule}-"
                f"{alert.get('source_ip') or 'unknown'}"
            )

            alert["title"] = (
                f"{alert.get('title', 'Security issue')} "
                f"({alert['event_count']} events)"
            )

            alert["reason"] = (
                f"{alert['event_count']} related events "
                f"grouped by {rule} for source "
                f"{alert.get('source_ip') or 'unknown'}."
            )

    return sorted(
        result,
        key=lambda item: item.get(
            "created_at",
            "",
        ),
        reverse=True,
    )


def evaluate_alerts(
    event: dict,
) -> list[dict]:

    now = time.time()

    ues = event.get("ues") or {}

    try:
        severity = int(
            ues.get("severity")
            or 0
        )
    except (
        TypeError,
        ValueError,
    ):
        severity = 0

    action = str(
        ues.get("action")
        or ""
    ).lower()

    outcome = str(
        ues.get("outcome")
        or ""
    ).lower()

    text = _event_text(
        event
    )

    source_ip = str(
        _get(
            event,
            "source.ip",
        )
        or ""
    )

    alerts = []

    def emit(
        rule,
        title,
        reason,
        severity_label="high",
        cooldown=60,
    ):

        key = _cooldown_key(
            rule,
            event,
        )

        if (
            now
            - _alert_cooldowns.get(
                key,
                0,
            )
            < cooldown
        ):
            return

        _alert_cooldowns[key] = now

        alerts.append({
            "alert_id":
                f"AL-{int(now * 1000)}-"
                f"{len(_alerts) + len(alerts) + 1}",

            "created_at":
                now_iso(),

            "rule":
                rule,

            "title":
                title,

            "severity":
                severity_label,

            "reason":
                reason,

            "trace_id":
                (
                    event.get("trace", {})
                    .get("trace_id")
                ),

            "source_ip":
                source_ip or None,

            "parser":
                (
                    event.get("meta", {})
                    .get("parser")
                ),

            "raw_hash":
                (
                    event.get("trace", {})
                    .get("raw_hash")
                ),

            "acknowledged":
                False,
        })

    failed_auth = (
        (
            "authentication"
            in str(
                ues.get(
                    "category",
                    "",
                )
            ).lower()
            or "auth" in text
            or "failed password" in text
            or "failed login" in text
            or "login failed" in text
        )
        and (
            "failed" in text
            or outcome == "failure"
            or action == "deny"
        )
    )

    threat = ues.get(
        "threat"
    ) or {}

    if threat.get(
        "matched"
    ):

        try:
            threat_score = int(
                threat.get("score")
                or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            threat_score = 0

        emit(
            "threat-intel-match",
            "Threat intelligence match",
            (
                f"Local threat-intel feed matched "
                f"{len(threat['matched'])} indicator(s)."
            ),
            (
                "critical"
                if threat_score >= 90
                else "high"
            ),
            300,
        )

    if (
        severity >= 80
        and not failed_auth
    ):

        emit(
            "high-severity",
            "High severity event",
            (
                f"Normalized event severity is "
                f"{severity}/100."
            ),
            (
                "critical"
                if severity >= 90
                else "high"
            ),
            60,
        )

    if (
        (
            action in {
                "deny",
                "drop",
                "blocked",
                "block",
                "reject",
            }
            or outcome == "failure"
        )
        and not failed_auth
    ):

        emit(
            "security-failure",
            "Security failure / denied action",
            (
                f"Normalized action={action or 'n/a'}, "
                f"outcome={outcome or 'n/a'}."
            ),
            "high",
            30,
        )

    if (
        failed_auth
        and source_ip
    ):

        history = [
            t
            for t in _alert_failed_auth.get(
                source_ip,
                [],
            )
            if now - t <= 300
        ]

        history.append(now)

        _alert_failed_auth[
            source_ip
        ] = history[-20:]

    return alerts


# ============================================================================
# OPTIONAL EXTERNAL ALERT WEBHOOK
# ============================================================================

def notify_external(
    alert: dict,
) -> None:

    url = os.environ.get(
        "ULPF_ALERT_WEBHOOK",
        "",
    ).strip()

    if not url:
        return

    # Count only outbound HTTP calls initiated by ULPF itself.
    _airgap_runtime["external_requests"] += 1
    try:
        host = urlparse(url).hostname or ""
        if host and host.lower() not in {"localhost", "127.0.0.1", "::1"} and not host.startswith(("10.", "192.168.", "172.")):
            _airgap_runtime["cloud_api_calls"] += 1
    except ValueError:
        pass

    body = json.dumps(
        alert,
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )

    try:

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type":
                    "application/json",
            },
            method="POST",
        )

        urllib.request.urlopen(
            req,
            timeout=5,
        ).read()

    except (
        urllib.error.URLError,
        OSError,
    ):
        pass


# ============================================================================
# OPTIONAL POSTGRESQL STORAGE
# ============================================================================

def _storage():
    """
    Return the optional PostgreSQL repository.

    CRITICAL AIR-GAPPED RULE:
    PostgreSQL is disabled by default.

    To enable it:
        $env:ULPF_ENABLE_POSTGRES="true"

    This prevents an unreachable PostgreSQL instance from blocking:
    - agent registration
    - heartbeat
    - ingest
    - local operation
    """

    global _storage_repo
    global _storage_error
    global _storage_attempted

    if not POSTGRES_ENABLED:

        _storage_error = (
            "PostgreSQL disabled; using local JSONL storage"
        )

        return None

    if get_repository is None:

        _storage_error = (
            "storage package unavailable"
        )

        _storage_attempted = True

        return None

    if _storage_repo is not None:
        return _storage_repo

    # Only one thread may initialize PostgreSQL.
    with _storage_lock:

        if _storage_repo is not None:
            return _storage_repo

        if _storage_attempted:
            return None

        _storage_attempted = True

        try:

            print(
                "[ULPF] PostgreSQL initialization requested..."
            )

            _storage_repo = get_repository()

            _storage_error = None

            print(
                "[ULPF] PostgreSQL storage connected."
            )

        except Exception as ex:

            _storage_repo = None

            _storage_error = str(
                ex
            )

            print(
                "[ULPF] PostgreSQL unavailable; "
                "continuing with local storage: "
                + str(ex)
            )

    return _storage_repo


def _optional_storage_call(
    operation_name: str,
    callback,
) -> None:
    """
    Persist to PostgreSQL only when explicitly enabled.

    PostgreSQL failures NEVER propagate into the HTTP request.
    """

    if not POSTGRES_ENABLED:
        return

    try:

        repo = _storage()

        if repo is None:
            return

        callback(repo)

    except Exception as ex:

        print(
            f"[ULPF] Optional PostgreSQL operation "
            f"{operation_name} skipped: {ex}"
        )


# ============================================================================
# EVENT RECORDING
# ============================================================================

def record_event(
    event: dict,
    write_outputs=True,
    raw: str | None = None,
):

    trace_id = str(
        (
            event.get("trace")
            or {}
        ).get(
            "trace_id"
        )
        or ""
    )

    # ---------------------------------------------------------
    # LOCAL EVENT STORAGE
    # ---------------------------------------------------------

    with _lock:

        if (
            trace_id
            and any(
                str(
                    (
                        item.get("trace")
                        or {}
                    ).get(
                        "trace_id"
                    )
                    or ""
                )
                == trace_id
                for item in _events
            )
        ):
            return event, []

        _events.append(
            event
        )

        if len(_events) > 1000:
            del _events[:-1000]

    # Local disk write OUTSIDE lock.
    _append_jsonl(
        EVENT_FILE,
        event,
    )

    # ---------------------------------------------------------
    # OPTIONAL POSTGRESQL
    # ---------------------------------------------------------

    _optional_storage_call(
        "save_event",
        lambda repo:
            repo.save_event(
                event,
                raw=(
                    raw
                    if raw is not None
                    else event.get("raw")
                ),
            ),
    )

    # ---------------------------------------------------------
    # ALERT EVALUATION
    # ---------------------------------------------------------

    new_alerts = evaluate_alerts(
        event
    )

    # ---------------------------------------------------------
    # CORRELATION
    # ---------------------------------------------------------

    try:

        correlation_result = (
            _correlation_engine.ingest(
                event
            )
        )

        if correlation_result:

            cases = correlation_result.get(
                "cases",
                [],
            )

            if cases:

                with _lock:

                    _correlations.extend(
                        cases
                    )

                    if len(
                        _correlations
                    ) > 500:

                        del _correlations[
                            :-500
                        ]

                for case in cases:

                    _optional_storage_call(
                        "save_correlation",
                        lambda repo,
                        case=case:
                            repo.save_correlation(
                                case
                            ),
                    )

            new_alerts.extend(
                correlation_result.get(
                    "alerts",
                    [],
                )
            )

    except Exception as ex:

        print(
            "[ULPF] correlation engine error: "
            + str(ex)
        )

    # ---------------------------------------------------------
    # ALERT STORAGE
    # ---------------------------------------------------------

    for alert in new_alerts:

        with _lock:

            _alerts.append(
                alert
            )

            if len(_alerts) > 500:
                del _alerts[:-500]

        _append_jsonl(
            ALERT_FILE,
            alert,
        )

        _optional_storage_call(
            "save_alert",
            lambda repo,
            alert=alert:
                repo.save_alert(
                    alert
                ),
        )

        threading.Thread(
            target=notify_external,
            args=(alert,),
            daemon=True,
        ).start()

    # ---------------------------------------------------------
    # OUTPUTS
    # ---------------------------------------------------------

    if write_outputs:

        for out in list(
            _runtime_outputs
        ):

            try:

                out.write(
                    [event]
                )

            except Exception as ex:

                print(
                    f"ULPF web output "
                    f"{getattr(out, 'name', 'unknown')} "
                    f"error: {ex}"
                )

    return event, new_alerts


# ============================================================================
# LIVE RUNTIME
# ============================================================================

def _runtime_worker():

    while not _runtime_stop.is_set():

        try:

            raw, meta = (
                _runtime_queue.get(
                    timeout=0.25
                )
            )

        except queue.Empty:
            continue

        try:

            event = _pipeline.process_raw(
                raw,
                meta,
            )

            record_event(
                event,
                write_outputs=True,
                raw=raw,
            )

        except Exception as ex:

            print(
                f"ULPF live ingest error: {ex}"
            )

        finally:

            _runtime_queue.task_done()


def start_live_runtime():

    global _runtime_queue
    global _runtime_sources
    global _runtime_outputs

    if _pipeline is None:
        init_app()

    if _runtime_queue is not None:
        return

    pipeline_cfg = (
        _pipeline.config.get(
            "pipeline"
        )
        or {}
    )

    queue_size = int(
        pipeline_cfg.get(
            "queue_size",
            50000,
        )
    )

    _runtime_queue = queue.Queue(
        maxsize=queue_size
    )

    _runtime_outputs = build_outputs(
        _pipeline.config.get(
            "outputs"
        )
        or []
    )

    for out in _runtime_outputs:

        try:

            out.open()

        except Exception as ex:

            print(
                f"ULPF output "
                f"{getattr(out, 'name', 'unknown')} "
                f"unavailable: {ex}"
            )

    _runtime_sources = build_sources(
        _pipeline.config.get(
            "inputs"
        )
        or [],
        _runtime_queue,
        _pipeline.stats,
    )

    for source in _runtime_sources:

        try:
            source.start()

        except Exception as ex:

            print(
                "[ULPF] Source start failed: "
                + str(ex)
            )

    workers = int(
        pipeline_cfg.get(
            "workers",
            4,
        )
    )

    for i in range(
        max(
            1,
            workers,
        )
    ):

        t = threading.Thread(
            target=_runtime_worker,
            daemon=True,
            name=f"ulpf-web-worker-{i}",
        )

        t.start()

        _runtime_threads.append(
            t
        )

    print(
        "[ULPF] Live runtime started."
    )


# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

def init_app():

    global _pipeline
    global _agents

    if _pipeline is not None:
        return

    cfg = load_pipeline_config(
        os.environ.get(
            "ULPF_CONFIG"
        )
    )

    specs = load_parser_specs(
        cfg
    )

    _pipeline = Pipeline(
        cfg,
        registry=ParserRegistry(
            specs
        ),
        enrichers=build_enrichers(
            cfg
        ),
    )

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    _load_jsonl(
        EVENT_FILE,
        _events,
        1000,
    )

    _load_jsonl(
        ALERT_FILE,
        _alerts,
        500,
    )

    # ---------------------------------------------------------
    # CORRELATION REHYDRATION
    # ---------------------------------------------------------

    _correlations.clear()

    for alert in _alerts:

        if (
            alert.get(
                "correlation_id"
            )
            or str(
                alert.get(
                    "rule_id",
                    "",
                )
            ).startswith(
                "correlation-"
            )
        ):

            _correlations.append({

                "correlation_id":
                    alert.get(
                        "correlation_id"
                    )
                    or alert.get(
                        "alert_id"
                    ),

                "created_at":
                    alert.get(
                        "created_at"
                    ),

                "first_seen":
                    alert.get(
                        "first_seen"
                    )
                    or alert.get(
                        "created_at"
                    ),

                "last_seen":
                    alert.get(
                        "last_seen"
                    )
                    or alert.get(
                        "created_at"
                    ),

                "rule_id":
                    alert.get(
                        "rule_id"
                    )
                    or alert.get(
                        "rule"
                    ),

                "type":
                    alert.get(
                        "correlation_type"
                    )
                    or str(
                        alert.get(
                            "rule_id",
                            "",
                        )
                    ).replace(
                        "correlation-",
                        "",
                    ),

                "title":
                    alert.get(
                        "title"
                    ),

                "description":
                    alert.get(
                        "description"
                    )
                    or alert.get(
                        "reason"
                    ),

                "risk_score":
                    alert.get(
                        "risk_score"
                    ),

                "severity":
                    alert.get(
                        "severity"
                    ),

                "source_ip":
                    alert.get(
                        "source_ip"
                    ),

                "user":
                    alert.get(
                        "user"
                    ),

                "event_count":
                    alert.get(
                        "event_count"
                    )
                    or len(
                        alert.get(
                            "evidence_trace_ids"
                        )
                        or []
                    ),

                "trace_ids":
                    alert.get(
                        "trace_ids"
                    )
                    or alert.get(
                        "evidence_trace_ids"
                    )
                    or [],

                "evidence":
                    alert.get(
                        "evidence"
                    )
                    or [],

                "explanation":
                    alert.get(
                        "explanation"
                    )
                    or {},
            })

    if len(_correlations) > 500:
        del _correlations[:-500]

    known_correlation_ids = {
        case.get(
            "correlation_id"
        )
        for case in _correlations
    }

    for event in _events:

        try:

            result = (
                _correlation_engine.ingest(
                    event
                )
            )

        except Exception as ex:

            print(
                "[ULPF] correlation rehydration error: "
                + str(ex)
            )

            continue

        for case in (
            result or {}
        ).get(
            "cases",
            [],
        ):

            correlation_id = case.get(
                "correlation_id"
            )

            if (
                correlation_id
                not in known_correlation_ids
            ):

                _correlations.append(
                    case
                )

                known_correlation_ids.add(
                    correlation_id
                )

    if len(_correlations) > 500:
        del _correlations[:-500]

    # ---------------------------------------------------------
    # AGENT REGISTRY
    # ---------------------------------------------------------

    try:

        if AGENT_FILE.exists():

            loaded_agents = json.loads(
                AGENT_FILE.read_text(
                    encoding="utf-8"
                )
            )

            _agents = (
                loaded_agents
                if isinstance(
                    loaded_agents,
                    dict,
                )
                else {}
            )

        else:

            _agents = {}

    except (
        OSError,
        ValueError,
        TypeError,
    ):

        _agents = {}

    print(
        "[ULPF] Application initialized "
        "(local-first / air-gapped)"
    )

    print(
        "[ULPF] PostgreSQL enabled: "
        + str(POSTGRES_ENABLED)
    )


# ============================================================================
# PROCESS API
# ============================================================================

def process(
    raw: str,
    source_type="web",
    address="web",
    transport="http",
):

    if _pipeline is None:
        init_app()

    event = _pipeline.process_raw(
        raw,
        {
            "source_type":
                source_type,

            "address":
                address,

            "received_time":
                now_iso(),

            "transport":
                transport,
        },
    )

    return record_event(
        event,
        write_outputs=False,
        raw=raw,
    )[0]


# ============================================================================
# SYSTEM LOG DISCOVERY
# ============================================================================

def system_log_files():

    found = []
    seen = set()

    for base in HOST_LOG_DIRS:

        if not base.exists():
            continue

        try:

            for p in base.rglob("*"):

                if (
                    p.is_file()
                    and p.suffix.lower()
                    in {
                        ".log",
                        ".txt",
                    }
                ):

                    try:
                        rp = str(
                            p.resolve()
                        )
                    except OSError:
                        rp = str(p)

                    if rp not in seen:

                        seen.add(rp)
                        found.append(p)

                if len(found) >= 100:
                    break

        except OSError:
            continue

        if len(found) >= 100:
            break

    return found[:100]


def read_system_logs(
    limit=100,
):

    limit = max(
        1,
        min(
            int(limit),
            500,
        ),
    )

    rows = []

    for p in system_log_files():

        try:

            lines = p.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()

        except OSError:
            continue

        for line in lines[-limit:]:

            if line.strip():

                rows.append({
                    "file":
                        str(p),

                    "raw":
                        line,
                })

        if len(rows) >= limit:
            break

    return rows[:limit]


# ============================================================================
# AUTHENTICATION
# ============================================================================

def _agent_token_ok(
    handler,
):

    expected = os.environ.get(
        "ULPF_AGENT_TOKEN",
        "Tnikita1800",
    ).strip()

    if not expected:

        return _env_true(
            "ULPF_ALLOW_UNAUTHENTICATED_AGENT",
            False,
        )

    value = handler.headers.get(
        "Authorization",
        "",
    )

    return hmac.compare_digest(value, "Bearer " + expected)

    return hmac.compare_digest(
        value,
        f"Bearer {expected}",
    )


def _operator_token_ok(
    handler,
):

    expected = os.environ.get(
        "ULPF_OPERATOR_TOKEN",
        "",
    ).strip()

    if not expected:
        return True

    value = handler.headers.get(
        "Authorization",
        "",
    )

    return hmac.compare_digest(value, "Bearer " + expected)

    return hmac.compare_digest(
        value,
        f"Bearer {expected}",
    )


# ============================================================================
# AGENT LOCAL REGISTRY
# ============================================================================

def _save_agents():

    try:

        AGENT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        tmp = AGENT_FILE.with_suffix(
            ".tmp"
        )

        tmp.write_text(
            json.dumps(
                _agents,
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        tmp.replace(
            AGENT_FILE
        )

    except OSError as ex:

        print(
            "[ULPF] Agent registry save failed: "
            + repr(ex)
        )


def _agent_status(
    agent,
):

    age = (
        time.time()
        - float(
            agent.get(
                "last_seen_epoch",
                0,
            )
            or 0
        )
    )

    return (
        "online"
        if age <= 30
        else (
            "stale"
            if age <= 180
            else "offline"
        )
    )


# ============================================================================
# SAFE QUERY INTEGER
# ============================================================================

def _query_int(
    query,
    name,
    default,
    minimum,
    maximum,
):

    try:

        value = int(
            (
                query.get(
                    name
                )
                or [str(default)]
            )[0]
        )

    except (
        ValueError,
        TypeError,
    ):

        value = default

    return max(
        minimum,
        min(
            value,
            maximum,
        ),
    )


# ============================================================================
# JSON RESPONSE
# ============================================================================

def json_response(
    handler,
    payload,
    status=200,
):

    body = json.dumps(
        payload,
        ensure_ascii=False,
        default=str,
    ).encode(
        "utf-8"
    )

    try:

        handler.send_response(
            status
        )

        handler.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )

        handler.send_header(
            "Content-Length",
            str(len(body)),
        )

        handler.send_header(
            "Cache-Control",
            "no-store",
        )

        handler.end_headers()

        handler.wfile.write(
            body
        )

    except (
        BrokenPipeError,
        ConnectionResetError,
    ):
        pass


# ============================================================================
# AIR-GAP SECURITY STATUS
# ============================================================================

_airgap_runtime = {
    "external_requests": 0,
    "cloud_api_calls": 0,
    "external_dns_requests": 0,
}


def _airgap_status():
    """Return a truthful local runtime air-gap status.

    This reports ULPF-controlled external configuration and outbound calls.
    It is not an OS-wide packet/DNS monitor.
    """
    external_endpoints = []
    config_candidates = [
        ROOT / "configs",
        ROOT / "agent" / "agent.yaml",
        ROOT / "docker-compose.yml",
        ROOT / ".env.example",
    ]
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "postgres", "kafka", "elasticsearch"}

    import re
    for cfg in config_candidates:
        if not cfg.exists() or not cfg.is_file():
            if cfg.is_dir():
                try:
                    files = list(cfg.rglob("*"))[:500]
                except OSError:
                    files = []
            else:
                files = []
        else:
            files = [cfg]
        for item in files:
            if not item.is_file():
                continue
            try:
                text = item.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in re.finditer(r'https?://([^/\s"\']+)', text, re.I):
                host = match.group(1).split(":", 1)[0].lower()
                if host not in allowed_hosts and not host.startswith(("10.", "192.168.", "172.")):
                    if host not in external_endpoints:
                        external_endpoints.append(host)

    external_count = len(external_endpoints)
    network_required = external_count > 0 or bool(os.environ.get("ULPF_ALERT_WEBHOOK", "").strip())
    status = "PASS" if not network_required else "WARN"

    return {
        "status": status,
        "external_endpoints": external_count,
        "cloud_api_calls": _airgap_runtime["cloud_api_calls"],
        "external_requests": _airgap_runtime["external_requests"],
        "external_dns_requests": _airgap_runtime["external_dns_requests"],
        "network_access_required": network_required,
        "mode": "air-gapped" if not network_required else "private-network",
        "audit": {
            "performed_offline": True,
            "scope": "ULPF runtime/configuration",
        },
    }


# ============================================================================
# HTTP HANDLER
# ============================================================================

class Handler(
    BaseHTTPRequestHandler
):

    server_version = "ULPF-Web/2.0"

    MAX_BODY = int(
        os.environ.get(
            "ULPF_MAX_BODY_BYTES",
            str(2 * 1024 * 1024),
        )
    )

    def setup(self):

        super().setup()

        # Prevent permanently hanging client connections.
        try:
            self.connection.settimeout(
                30
            )
        except OSError:
            pass

    def log_message(
        self,
        fmt,
        *args,
    ):

        print(
            "[ULPF web] "
            + fmt % args
        )

    # ========================================================================
    # GET
    # ========================================================================

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        # Operator authentication.
        if (
            path.startswith("/api/")
            and path not in {
                "/api/health",
                "/api/live",
                "/api/ready",
            }
            and not _operator_token_ok(
                self
            )
        ):

            return json_response(
                self,
                {
                    "error":
                        "unauthorized",

                    "error_code":
                        "unauthorized",

                    "message":
                        "operator authentication required",
                },
                401,
            )

        # --------------------------------------------------------------------
        # AIR-GAP SECURITY STATUS
        # --------------------------------------------------------------------
        if path == "/api/security/airgap":
            return json_response(
                self,
                _airgap_status(),
            )

        # --------------------------------------------------------------------
        # HEALTH
        # --------------------------------------------------------------------

        if path == "/api/health":

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "service":
                        "ULPF",

                    "time":
                        now_iso(),

                    "live_ingestion":
                        _runtime_queue is not None,

                    "postgresql":
                        _storage_repo is not None,

                    "postgresql_enabled":
                        POSTGRES_ENABLED,

                    "backend":
                        (
                            "postgresql"
                            if _storage_repo is not None
                            else "jsonl-local"
                        ),
                },
            )

        # --------------------------------------------------------------------
        # LIVE
        # --------------------------------------------------------------------

        if path == "/api/live":

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "service":
                        "ULPF",

                    "time":
                        now_iso(),
                },
            )

        # --------------------------------------------------------------------
        # READY
        # --------------------------------------------------------------------

        if path == "/api/ready":

            # IMPORTANT:
            # DO NOT call _storage() here.
            #
            # Readiness must never wait for PostgreSQL.
            #
            # If PostgreSQL is enabled and already connected, report it.
            # Otherwise report local readiness.

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "service":
                        "ULPF",

                    "postgresql":
                        _storage_repo is not None,

                    "postgresql_enabled":
                        POSTGRES_ENABLED,

                    "backend":
                        (
                            "postgresql"
                            if _storage_repo is not None
                            else "local-fallback"
                        ),

                    "message":
                        (
                            "Local air-gapped storage is ready"
                        ),
                },
            )

        # --------------------------------------------------------------------
        # STORAGE
        # --------------------------------------------------------------------

        if path == "/api/storage":

            repo = (
                _storage()
                if POSTGRES_ENABLED
                else None
            )

            return json_response(
                self,
                {
                    "ok":
                        repo is not None,

                    "backend":
                        (
                            "postgresql"
                            if repo is not None
                            else "jsonl-fallback"
                        ),

                    "postgresql_enabled":
                        POSTGRES_ENABLED,

                    "error":
                        _storage_error,
                },
            )

        # --------------------------------------------------------------------
        # EVENTS
        # --------------------------------------------------------------------

        if path == "/api/events":

            q = parse_qs(
                parsed.query
            )

            limit = _query_int(
                q,
                "limit",
                50,
                1,
                200,
            )

            page = _query_int(
                q,
                "page",
                1,
                1,
                1000000,
            )

            offset = (
                page - 1
            ) * limit

            repo = _storage_repo

            if repo is not None:

                try:

                    events = repo.list_events(
                        limit,
                        offset,
                    )

                except TypeError:

                    events = repo.list_events(
                        limit
                    )

                except Exception as ex:

                    print(
                        "[ULPF] PostgreSQL event read failed: "
                        + str(ex)
                    )

                    with _lock:

                        events = list(
                            reversed(
                                _events
                            )
                        )[
                            offset:
                            offset + limit
                        ]

            else:

                with _lock:

                    events = list(
                        reversed(
                            _events
                        )
                    )[
                        offset:
                        offset + limit
                    ]

            return json_response(
                self,
                {
                    "events":
                        events,

                    "count":
                        len(events),

                    "page":
                        page,

                    "limit":
                        limit,

                    "next_page":
                        (
                            page + 1
                            if len(events) == limit
                            else None
                        ),
                },
            )

        # --------------------------------------------------------------------
        # CORRELATIONS
        # --------------------------------------------------------------------

        if path == "/api/correlations":

            q = parse_qs(
                parsed.query
            )

            limit = _query_int(
                q,
                "limit",
                50,
                1,
                200,
            )

            repo = _storage_repo

            if repo is not None:

                try:

                    cases = (
                        repo.list_correlations(
                            limit
                        )
                    )

                except Exception:

                    with _lock:

                        cases = list(
                            reversed(
                                _correlations[
                                    -limit:
                                ]
                            )
                        )

            else:

                with _lock:

                    cases = list(
                        reversed(
                            _correlations[
                                -limit:
                            ]
                        )
                    )

            return json_response(
                self,
                {
                    "correlations":
                        cases,

                    "count":
                        len(cases),
                },
            )

        # --------------------------------------------------------------------
        # CORRELATION DETAIL
        # --------------------------------------------------------------------

        if (
            path.startswith(
                "/api/correlations/"
            )
            and path.count("/") == 3
        ):

            correlation_id = (
                unquote(
                    path.split("/")[3]
                )
            )

            case = None

            if _storage_repo is not None:

                try:

                    case = next(
                        (
                            item
                            for item
                            in _storage_repo.list_correlations(
                                500
                            )
                            if item.get(
                                "correlation_id"
                            )
                            == correlation_id
                        ),
                        None,
                    )

                except Exception:
                    case = None

            if case is None:

                with _lock:

                    case = next(
                        (
                            c
                            for c in _correlations
                            if c.get(
                                "correlation_id"
                            )
                            == correlation_id
                        ),
                        None,
                    )

            if not case:

                return json_response(
                    self,
                    {
                        "error":
                            "correlation not found",
                    },
                    404,
                )

            return json_response(
                self,
                case,
            )

        # --------------------------------------------------------------------
        # ALERTS
        # --------------------------------------------------------------------

        if path == "/api/alerts":

            q = parse_qs(
                parsed.query
            )

            limit = _query_int(
                q,
                "limit",
                50,
                1,
                200,
            )

            page = _query_int(
                q,
                "page",
                1,
                1,
                1000000,
            )

            offset = (
                page - 1
            ) * limit

            repo = _storage_repo

            if repo is not None:

                try:

                    alerts = repo.list_alerts(
                        limit,
                        offset,
                    )

                except TypeError:

                    alerts = repo.list_alerts(
                        limit
                    )

                except Exception:

                    with _lock:

                        alerts = _group_alerts(
                            _alerts
                        )[
                            offset:
                            offset + limit
                        ]

            else:

                with _lock:

                    alerts = _group_alerts(
                        _alerts
                    )[
                        offset:
                        offset + limit
                    ]

            return json_response(
                self,
                {
                    "alerts":
                        alerts,

                    "count":
                        len(alerts),

                    "page":
                        page,

                    "limit":
                        limit,

                    "next_page":
                        (
                            page + 1
                            if len(alerts) == limit
                            else None
                        ),
                },
            )

        # --------------------------------------------------------------------
        # ALERT TRACE
        # --------------------------------------------------------------------

        if (
            path.startswith(
                "/api/alerts/"
            )
            and path.endswith(
                "/trace"
            )
        ):

            parts = path.split("/")

            if len(parts) < 4:

                return json_response(
                    self,
                    {
                        "error":
                            "invalid alert path",
                    },
                    400,
                )

            alert_id = unquote(
                parts[3]
            )

            with _lock:

                grouped = _group_alerts(
                    _alerts
                )

                alert = next(
                    (
                        item
                        for item in grouped
                        if item.get(
                            "alert_id"
                        )
                        == alert_id
                    ),
                    None,
                )

                if alert is None:

                    alert = next(
                        (
                            item
                            for item in _alerts
                            if item.get(
                                "alert_id"
                            )
                            == alert_id
                        ),
                        None,
                    )

                if alert is None:

                    return json_response(
                        self,
                        {
                            "error":
                                "alert not found",
                        },
                        404,
                    )

                trace_ids = {
                    str(trace_id)
                    for trace_id in (
                        alert.get(
                            "evidence_trace_ids"
                        )
                        or alert.get(
                            "trace_ids"
                        )
                        or [
                            alert.get(
                                "trace_id"
                            )
                        ]
                    )
                    if trace_id
                }

                events = [
                    event
                    for event in _events
                    if str(
                        (
                            event.get(
                                "trace"
                            )
                            or {}
                        ).get(
                            "trace_id"
                        )
                    )
                    in trace_ids
                ]

            return json_response(
                self,
                {
                    "alert":
                        alert,

                    "trace_ids":
                        list(trace_ids),

                    "events":
                        events,

                    "count":
                        len(events),
                },
            )

        # --------------------------------------------------------------------
        # EVENT LINEAGE
        # --------------------------------------------------------------------

        if (
            path.startswith(
                "/api/events/"
            )
            and path.endswith(
                "/lineage"
            )
        ):

            trace_id = unquote(
                path.split("/")[3]
            )

            with _lock:

                event = next(
                    (
                        e
                        for e in _events
                        if (
                            e.get(
                                "trace",
                                {},
                            ).get(
                                "trace_id"
                            )
                            == trace_id
                        )
                    ),
                    None,
                )

            if not event:

                return json_response(
                    self,
                    {
                        "error":
                            "event not found",
                    },
                    404,
                )

            trace = (
                event.get(
                    "trace"
                )
                or {}
            )

            return json_response(
                self,
                {
                    "trace_id":
                        trace_id,

                    "raw":
                        event.get(
                            "raw",
                            "",
                        ),

                    "raw_hash":
                        trace.get(
                            "raw_hash"
                        ),

                    "lineage":
                        trace.get(
                            "lineage",
                            [],
                        ),
                },
            )

        # --------------------------------------------------------------------
        # EVENT VERIFY
        # --------------------------------------------------------------------

        if (
            path.startswith(
                "/api/events/"
            )
            and path.endswith(
                "/verify"
            )
        ):

            trace_id = unquote(
                path.split("/")[3]
            )

            result = None

            if _storage_repo is not None:

                try:

                    result = (
                        _storage_repo.verify_raw(
                            trace_id
                        )
                    )

                except Exception:
                    result = None

            if result is None:

                with _lock:

                    event = next(
                        (
                            e
                            for e in _events
                            if (
                                e.get(
                                    "trace"
                                )
                                or {}
                            ).get(
                                "trace_id"
                            )
                            == trace_id
                        ),
                        None,
                    )

                if event is None:

                    return json_response(
                        self,
                        {
                            "error":
                                "event not found",

                            "error_code":
                                "not_found",

                            "message":
                                "event not found",
                        },
                        404,
                    )

                raw = str(
                    event.get(
                        "raw"
                    )
                    or ""
                ).encode(
                    "utf-8"
                )

                digest = hashlib.sha256(
                    raw
                ).hexdigest()

                expected = (
                    event.get(
                        "trace"
                    )
                    or {}
                ).get(
                    "raw_hash"
                )

                result = {
                    "trace_id":
                        trace_id,

                    "recorded_hash":
                        expected,

                    "computed_hash":
                        digest,

                    "verified":
                        bool(
                            expected
                            and expected == digest
                        ),
                }

            return json_response(
                self,
                result,
            )

        # --------------------------------------------------------------------
        # EVENT EXPORT
        # --------------------------------------------------------------------

        if path == "/api/events/export":

            q = parse_qs(
                parsed.query
            )

            limit = _query_int(
                q,
                "limit",
                1000,
                1,
                10000,
            )

            repo = _storage_repo

            if repo is not None:

                try:

                    rows = (
                        repo.export_events(
                            limit
                        )
                    )

                except Exception:

                    with _lock:

                        rows = list(
                            reversed(
                                _events[
                                    -limit:
                                ]
                            )
                        )

            else:

                with _lock:

                    rows = list(
                        reversed(
                            _events[
                                -limit:
                            ]
                        )
                    )

            return json_response(
                self,
                {
                    "events":
                        rows,

                    "count":
                        len(rows),

                    "format":
                        "json",
                },
            )

        # --------------------------------------------------------------------
        # AGENT PLUGIN DOWNLOAD
        # --------------------------------------------------------------------

        if path == "/api/agent-plugin/download":

            bundle = (
                ROOT
                / "dist"
                / "ULPF-Agent-Plugin.zip"
            )

            if not bundle.is_file():

                return json_response(
                    self,
                    {
                        "error":
                            "agent plugin bundle not built",
                    },
                    404,
                )

            try:
                data = bundle.read_bytes()
            except OSError as ex:

                return json_response(
                    self,
                    {
                        "error":
                            "unable to read plugin bundle",
                        "message":
                            str(ex),
                    },
                    500,
                )

            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                "application/zip",
            )

            self.send_header(
                "Content-Disposition",
                'attachment; filename="ULPF-Agent-Plugin.zip"',
            )

            self.send_header(
                "Content-Length",
                str(len(data)),
            )

            self.send_header(
                "Cache-Control",
                "no-store",
            )

            self.end_headers()

            try:
                self.wfile.write(
                    data
                )
            except (
                BrokenPipeError,
                ConnectionResetError,
            ):
                pass

            return

        # ====================================================================
        # AGENTS
        # ====================================================================

        if path == "/api/agents":

            with _lock:

                rows = []

                for a in _agents.values():

                    item = dict(
                        a
                    )

                    item["status"] = (
                        _agent_status(a)
                    )

                    rows.append(
                        item
                    )

            return json_response(
                self,
                {
                    "agents":
                        sorted(
                            rows,
                            key=lambda x:
                                x.get(
                                    "last_seen_epoch",
                                    0,
                                ),
                            reverse=True,
                        ),
                },
            )

        if (
            path.startswith(
                "/api/agents/"
            )
            and path.count("/") == 3
        ):

            aid = unquote(
                path.split("/")[3]
            )

            with _lock:

                a = _agents.get(
                    aid
                )

                if not a:

                    return json_response(
                        self,
                        {
                            "error":
                                "agent not found",
                        },
                        404,
                    )

                item = dict(
                    a
                )

                item["status"] = (
                    _agent_status(a)
                )

            return json_response(
                self,
                item,
            )

        # --------------------------------------------------------------------
        # PLUGINS
        # --------------------------------------------------------------------

        if path == "/api/plugins":

            if _pipeline is None:
                init_app()

            plugins = []

            for entry in (
                _pipeline.registry.entries
            ):

                spec = entry.get(
                    "spec"
                )

                if spec:

                    plugins.append({
                        "id":
                            spec.id,

                        "name":
                            spec.name,

                        "vendor":
                            spec.vendor,

                        "product":
                            spec.product,

                        "version":
                            spec.version,

                        "format":
                            spec.format,

                        "priority":
                            spec.priority,

                        "contract":
                            "ULPF-Plugin-v1",
                    })

            try:

                plugins.extend(
                    discover_plugins(
                        os.environ.get(
                            "ULPF_PLUGIN_DIR",
                            str(
                                ROOT
                                / "plugins"
                            ),
                        )
                    )
                )

            except Exception as ex:

                print(
                    "[ULPF] Plugin discovery failed: "
                    + str(ex)
                )

            return json_response(
                self,
                {
                    "plugins":
                        plugins,
                },
            )

        # --------------------------------------------------------------------
        # SYSTEM LOGS
        # --------------------------------------------------------------------

        if path == "/api/system-logs":

            q = parse_qs(
                parsed.query
            )

            limit = _query_int(
                q,
                "limit",
                100,
                1,
                500,
            )

            return json_response(
                self,
                {
                    "files":
                        [
                            str(p)
                            for p
                            in system_log_files()
                        ],

                    "rows":
                        read_system_logs(
                            limit
                        ),
                },
            )

        # --------------------------------------------------------------------
        # STATS
        # --------------------------------------------------------------------

        if path == "/api/stats":

            if _pipeline is None:
                init_app()

            stats = (
                _pipeline.stats.snapshot()
            )

            stats[
                "correlation"
            ] = (
                _correlation_engine.stats()
            )

            stats[
                "active_correlations"
            ] = len(
                _correlations
            )

            stats[
                "postgresql"
            ] = (
                _storage_repo is not None
            )

            stats[
                "postgresql_enabled"
            ] = POSTGRES_ENABLED

            stats[
                "storage_backend"
            ] = (
                "postgresql"
                if _storage_repo is not None
                else "jsonl-local"
            )

            return json_response(
                self,
                stats,
            )

        # --------------------------------------------------------------------
        # ONBOARDING FIELDS
        # --------------------------------------------------------------------

        if path == "/api/onboarding/fields":

            return json_response(
                self,
                {
                    "contract":
                        "ULPF-Plugin-v1",

                    "required": [
                        "manifest.yaml",
                        "parser.py",
                        "mappings.yaml",
                        "tests/",
                    ],
                },
            )

        return self.serve_static(
            path
        )

    # ========================================================================
    # STATIC FILES
    # ========================================================================

    def serve_static(
        self,
        path,
    ):

        if path in (
            "",
            "/",
        ):
            path = "/index.html"

        target = (
            STATIC
            / path.lstrip("/")
        ).resolve()

        try:

            target.relative_to(
                STATIC.resolve()
            )

        except ValueError:

            return json_response(
                self,
                {
                    "error":
                        "not found",
                },
                404,
            )

        if not target.is_file():

            target = (
                STATIC
                / "index.html"
            )

        try:

            data = target.read_bytes()

        except OSError as ex:

            return json_response(
                self,
                {
                    "error":
                        "static file read failed",

                    "message":
                        str(ex),
                },
                500,
            )

        mime = {
            ".html":
                "text/html; charset=utf-8",

            ".css":
                "text/css; charset=utf-8",

            ".js":
                "application/javascript; charset=utf-8",

            ".svg":
                "image/svg+xml",

            ".json":
                "application/json; charset=utf-8",

            ".png":
                "image/png",

            ".jpg":
                "image/jpeg",

            ".jpeg":
                "image/jpeg",

            ".ico":
                "image/x-icon",
        }.get(
            target.suffix.lower(),
            "application/octet-stream",
        )

        self.send_response(
            200
        )

        self.send_header(
            "Content-Type",
            mime,
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.end_headers()

        try:

            self.wfile.write(
                data
            )

        except (
            BrokenPipeError,
            ConnectionResetError,
        ):
            pass

    # ========================================================================
    # POST
    # ========================================================================

    def do_POST(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        # --------------------------------------------------------------------
        # Operator authentication.
        #
        # Agent endpoints are authenticated separately.
        # --------------------------------------------------------------------

        if (
            path.startswith("/api/")
            and path not in {
                "/api/agents/register",
                "/api/agents/heartbeat",
                "/api/ingest-agent",
            }
            and not _operator_token_ok(
                self
            )
        ):

            return json_response(
                self,
                {
                    "error":
                        "unauthorized",

                    "error_code":
                        "unauthorized",

                    "message":
                        "operator authentication required",
                },
                401,
            )

        # --------------------------------------------------------------------
        # Content-Length
        # --------------------------------------------------------------------

        try:

            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )

        except ValueError:

            return json_response(
                self,
                {
                    "error":
                        "invalid content length",
                },
                400,
            )

        if (
            length < 0
            or length > self.MAX_BODY
        ):

            return json_response(
                self,
                {
                    "error":
                        "request too large",

                    "error_code":
                        "payload_too_large",
                },
                413,
            )

        # --------------------------------------------------------------------
        # Request body
        # --------------------------------------------------------------------

        try:

            body = self.rfile.read(
                length
            )

        except (
            TimeoutError,
            OSError,
        ):

            return json_response(
                self,
                {
                    "error":
                        "request body read failed",
                },
                408,
            )

        # --------------------------------------------------------------------
        # JSON
        # --------------------------------------------------------------------

        try:

            payload = (
                json.loads(
                    body.decode(
                        "utf-8"
                    )
                )
                if body
                else {}
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):

            return json_response(
                self,
                {
                    "error":
                        "request body must be valid UTF-8 JSON",
                },
                400,
            )

        if not isinstance(
            payload,
            dict,
        ):

            return json_response(
                self,
                {
                    "error":
                        "request body must be a JSON object",
                },
                400,
            )

        # ====================================================================
        # AGENT REGISTER
        # ====================================================================

        if path == "/api/agents/register":

            # ---------------------------------------------------------------
            # AUTH FIRST
            # ---------------------------------------------------------------

            if not _agent_token_ok(
                self
            ):

                print(
                    "[ULPF] Agent registration rejected: unauthorized"
                )

                return json_response(
                    self,
                    {
                        "error":
                            "unauthorized",

                        "error_code":
                            "unauthorized",
                    },
                    401,
                )

            aid = str(
                payload.get(
                    "agent_id",
                    "",
                )
            ).strip()

            if not aid:

                return json_response(
                    self,
                    {
                        "error":
                            "agent_id required",
                    },
                    400,
                )

            now = time.time()

            # ---------------------------------------------------------------
            # BUILD AGENT OBJECT
            # ---------------------------------------------------------------

            with _lock:

                existing = _agents.get(
                    aid,
                    {},
                )

                a = {
                    "agent_id":
                        aid,

                    "name":
                        payload.get(
                            "name"
                        )
                        or aid,

                    "hostname":
                        payload.get(
                            "hostname"
                        ),

                    "os":
                        payload.get(
                            "os"
                        ),

                    "agent_version":
                        payload.get(
                            "agent_version",
                            "unknown",
                        ),

                    "sources":
                        payload.get(
                            "sources",
                            [],
                        ),

                    "capabilities":
                        payload.get(
                            "capabilities",
                            {},
                        ),

                    "discovery":
                        payload.get(
                            "discovery",
                            {},
                        ),

                    "registered_at":
                        existing.get(
                            "registered_at",
                            now_iso(),
                        ),

                    "last_seen":
                        now_iso(),

                    "last_seen_epoch":
                        now,

                    "queue_size":
                        0,
                }

                _agents[aid] = a

            # ---------------------------------------------------------------
            # LOCAL SAVE
            #
            # This MUST happen before optional DB.
            # ---------------------------------------------------------------

            _save_agents()

            print(
                "[ULPF] Agent registered locally: "
                + aid
            )

            # ---------------------------------------------------------------
            # OPTIONAL DB
            #
            # IMPORTANT:
            # This is deliberately AFTER the local response state.
            #
            # If PostgreSQL is disabled (default), this does nothing.
            # ---------------------------------------------------------------

            _optional_storage_call(
                "upsert_agent",
                lambda repo:
                    repo.upsert_agent(
                        a
                    ),
            )

            # ---------------------------------------------------------------
            # RESPONSE
            # ---------------------------------------------------------------

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "agent":
                        a,

                    "backend":
                        "postgresql"
                        if _storage_repo is not None
                        else "local",
                },
            )

        # ====================================================================
        # AGENT HEARTBEAT
        # ====================================================================

        if path == "/api/agents/heartbeat":

            if not _agent_token_ok(
                self
            ):

                return json_response(
                    self,
                    {
                        "error":
                            "unauthorized",

                        "error_code":
                            "unauthorized",
                    },
                    401,
                )

            aid = str(
                payload.get(
                    "agent_id",
                    "",
                )
            ).strip()

            if not aid:

                return json_response(
                    self,
                    {
                        "error":
                            "agent_id required",
                    },
                    400,
                )

            with _lock:

                if aid not in _agents:

                    return json_response(
                        self,
                        {
                            "error":
                                "agent not registered",
                        },
                        404,
                    )

                _agents[aid].update({

                    "last_seen":
                        now_iso(),

                    "last_seen_epoch":
                        time.time(),

                    "queue_size":
                        int(
                            payload.get(
                                "queue_size",
                                0,
                            )
                            or 0
                        ),
                })

                a = dict(
                    _agents[aid]
                )

                a["status"] = "online"

            _save_agents()

            _optional_storage_call(
                "upsert_agent_heartbeat",
                lambda repo:
                    repo.upsert_agent(
                        a
                    ),
            )

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "agent":
                        a,
                },
            )

        # ====================================================================
        # AGENT INGEST
        # ====================================================================

        if path == "/api/ingest-agent":

            if not _agent_token_ok(
                self
            ):

                return json_response(
                    self,
                    {
                        "error":
                            "unauthorized",

                        "error_code":
                            "unauthorized",
                    },
                    401,
                )

            aid = str(
                payload.get(
                    "agent_id"
                )
                or self.headers.get(
                    "X-ULPF-Agent-ID",
                    "",
                )
            ).strip()

            batch = (
                payload.get(
                    "events"
                )
                or []
            )

            if (
                not aid
                or not isinstance(
                    batch,
                    list,
                )
            ):

                return json_response(
                    self,
                    {
                        "error":
                            "agent_id and events[] required",
                    },
                    400,
                )

            if _runtime_queue is None:
                start_live_runtime()

            accepted = 0
            ack_ids = []
            rejected = 0

            for item in batch:

                if (
                    not isinstance(
                        item,
                        dict,
                    )
                    or not str(
                        item.get(
                            "raw",
                            "",
                        )
                    ).strip()
                ):

                    rejected += 1
                    continue

                fingerprint = hashlib.sha256(
                    json.dumps(
                        {
                            k: v
                            for k, v
                            in item.items()
                            if k != "_spool_id"
                        },
                        sort_keys=True,
                        default=str,
                    ).encode(
                        "utf-8"
                    )
                ).hexdigest()

                meta = {
                    k:
                        item.get(k)
                    for k in (
                        "source_type",
                        "address",
                        "transport",
                        "received_time",
                        "offset",
                        "agent_id",
                        "agent_name",
                    )
                    if item.get(k)
                    is not None
                }

                meta[
                    "agent_fingerprint"
                ] = fingerprint

                try:

                    _runtime_queue.put_nowait(
                        (
                            str(
                                item[
                                    "raw"
                                ]
                            ),
                            meta,
                        )
                    )

                    accepted += 1

                    if (
                        item.get(
                            "_spool_id"
                        )
                        is not None
                    ):

                        ack_ids.append(
                            item[
                                "_spool_id"
                            ]
                        )

                    # Optional receipt.
                    _optional_storage_call(
                        "claim_agent_receipt",
                        lambda repo,
                        aid=aid,
                        fingerprint=fingerprint:
                            repo.claim_agent_receipt(
                                aid,
                                fingerprint,
                            ),
                    )

                except queue.Full:

                    rejected += 1

                    break

            # Any items not accepted are rejected.
            if len(batch) > accepted + rejected:
                rejected += (
                    len(batch)
                    - accepted
                    - rejected
                )

            with _lock:

                if aid in _agents:

                    _agents[aid].update({

                        "last_seen":
                            now_iso(),

                        "last_seen_epoch":
                            time.time(),

                        "queue_size":
                            int(
                                payload.get(
                                    "queue_size",
                                    0,
                                )
                                or 0
                            ),
                    })

                    agent_snapshot = dict(
                        _agents[aid]
                    )

                else:

                    agent_snapshot = None

            _save_agents()

            if agent_snapshot is not None:

                _optional_storage_call(
                    "upsert_agent_ingest",
                    lambda repo:
                        repo.upsert_agent(
                            agent_snapshot
                        ),
                )

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "accepted":
                        accepted,

                    "rejected":
                        rejected,

                    "ack_ids":
                        ack_ids,
                },
            )

        # ====================================================================
        # NORMALIZE
        # ====================================================================

        if path == "/api/normalize":

            raw = payload.get(
                "raw"
            )

            if (
                not isinstance(
                    raw,
                    str,
                )
                or not raw.strip()
            ):

                return json_response(
                    self,
                    {
                        "error":
                            "raw must be a non-empty string",
                    },
                    400,
                )

            events = []

            for line in raw.splitlines():

                if not line.strip():
                    continue

                events.append(
                    process(
                        line,
                        payload.get(
                            "source_type",
                            "web",
                        ),
                        payload.get(
                            "address",
                            "web",
                        ),
                        payload.get(
                            "transport",
                            "http",
                        ),
                    )
                )

            return json_response(
                self,
                {
                    "events":
                        events,

                    "count":
                        len(events),
                },
            )

        # ====================================================================
        # NORMALIZE SYSTEM
        # ====================================================================

        if path == "/api/normalize-system":

            try:

                limit = int(
                    payload.get(
                        "limit",
                        100,
                    )
                )

            except (
                ValueError,
                TypeError,
            ):

                limit = 100

            limit = max(
                1,
                min(
                    limit,
                    500,
                ),
            )

            rows = read_system_logs(
                limit
            )

            events = [
                process(
                    r["raw"],
                    "system",
                    r["file"],
                    "file",
                )
                for r in rows
            ]

            return json_response(
                self,
                {
                    "events":
                        events,

                    "count":
                        len(events),

                    "files":
                        [
                            r["file"]
                            for r in rows
                        ],
                },
            )

        # ====================================================================
        # ALERT ACK
        # ====================================================================

        if path == "/api/alerts/ack":

            alert_id = str(
                payload.get(
                    "alert_id",
                    "",
                )
            )

            if not alert_id:

                return json_response(
                    self,
                    {
                        "error":
                            "alert_id required",
                    },
                    400,
                )

            with _lock:

                grouped = next(
                    (
                        item
                        for item
                        in _group_alerts(
                            _alerts
                        )
                        if item.get(
                            "alert_id"
                        )
                        == alert_id
                    ),
                    None,
                )

                alert_ids = (
                    set(
                        grouped.get(
                            "alert_ids",
                            [],
                        )
                    )
                    if grouped
                    else {
                        alert_id
                    }
                )

                alert = next(
                    (
                        a
                        for a in _alerts
                        if a.get(
                            "alert_id"
                        )
                        in alert_ids
                    ),
                    None,
                )

                if not alert:

                    return json_response(
                        self,
                        {
                            "error":
                                "alert not found",
                        },
                        404,
                    )

                candidates = []

                for candidate in _alerts:

                    if (
                        candidate.get(
                            "alert_id"
                        )
                        not in alert_ids
                    ):
                        continue

                    candidate[
                        "acknowledged"
                    ] = True

                    candidates.append(
                        dict(candidate)
                    )

            # Local append outside lock.
            for candidate in candidates:

                _append_jsonl(
                    ALERT_FILE,
                    {
                        **candidate,
                        "acknowledged_at":
                            now_iso(),
                    },
                )

            # Optional PostgreSQL acknowledgement.
            for candidate in candidates:

                _optional_storage_call(
                    "save_alert_ack",
                    lambda repo,
                    candidate=candidate:
                        repo.save_alert(
                            candidate
                        ),
                )

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "alert":
                        alert,
                },
            )

        # ====================================================================
        # LOCAL AI ONBOARDING
        # ====================================================================

        if path == "/api/onboarding/analyze":

            raw = str(
                payload.get(
                    "raw",
                    "",
                )
            )

            if not raw.strip():

                return json_response(
                    self,
                    {
                        "error":
                            "raw required",
                    },
                    400,
                )

            result = offline_analyze(
                raw
            )

            suggestions = result.get(
                "suggestions",
                [],
            )

            return json_response(
                self,
                {
                    **result,

                    "message":
                        "Mapping runs locally. "
                        "No cloud API is required.",

                    "plugin_template": {
                        "id":
                            "custom-source-v1",

                        "format":
                            "key-value",

                        "contract":
                            "ULPF-Plugin-v1",

                        "mappings":
                            suggestions,
                    },
                },
            )

        # ====================================================================
        # GENERATE OFFLINE PLUGIN
        # ====================================================================

        if path == "/api/onboarding/generate-plugin":

            raw = str(
                payload.get(
                    "raw",
                    "",
                )
            )

            name = str(
                payload.get(
                    "plugin_id",
                    "custom-source-v1",
                )
            ).strip()

            if not raw.strip():

                return json_response(
                    self,
                    {
                        "error":
                            "raw required",
                    },
                    400,
                )

            if not re.fullmatch(
                r"[a-z0-9][a-z0-9_-]{2,48}",
                name,
            ):

                return json_response(
                    self,
                    {
                        "error":
                            "invalid plugin_id",
                    },
                    400,
                )

            analysis = offline_analyze(
                raw
            )

            plugin_dir = (
                ROOT
                / "plugins"
                / name
            )

            plugin_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            manifest = {
                "id":
                    name,

                "name":
                    name.replace(
                        "-",
                        " ",
                    ).title(),

                "version":
                    "1.0.0",

                "entrypoint":
                    "parser.py",

                "mapping_file":
                    "mappings.yaml",

                "test_directory":
                    "tests",

                "contract":
                    "ULPF-Plugin-v1",

                "offline":
                    True,
            }

            (
                plugin_dir
                / "manifest.yaml"
            ).write_text(
                "\n".join(
                    f"{k}: {json.dumps(v)}"
                    for k, v
                    in manifest.items()
                )
                + "\n",
                encoding="utf-8",
            )

            (
                plugin_dir
                / "mappings.yaml"
            ).write_text(
                json.dumps(
                    {
                        "mappings":
                            analysis.get(
                                "suggestions",
                                [],
                            ),

                        "generated_by":
                            "ULPF offline onboarding",
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            # Simple offline parser template.
            #
            # This intentionally generates a REVIEWABLE parser.
            # It is not silently activated.
            parser_code = '''import re


def parse(raw):
    result = {}

    # key=value
    pattern = re.compile(
        r"""([A-Za-z_][\\w.-]*)=(?:"([^"]*)"|'([^']*)'|([^\\s]+))"""
    )

    for match in pattern.finditer(raw):
        key = match.group(1)
        value = (
            match.group(2)
            if match.group(2) is not None
            else (
                match.group(3)
                if match.group(3) is not None
                else match.group(4)
            )
        )

        result[key] = value

    return result
'''

            (
                plugin_dir
                / "parser.py"
            ).write_text(
                parser_code,
                encoding="utf-8",
            )

            tests = (
                plugin_dir
                / "tests"
            )

            tests.mkdir(
                parents=True,
                exist_ok=True,
            )

            test_code = '''from parser import parse


def test_parse():
    result = parse(
        'src=192.0.2.1 dst=198.51.100.1'
    )

    assert result["src"] == "192.0.2.1"
    assert result["dst"] == "198.51.100.1"
'''

            (
                tests
                / "test_plugin.py"
            ).write_text(
                test_code,
                encoding="utf-8",
            )

            return json_response(
                self,
                {
                    "ok":
                        True,

                    "plugin_id":
                        name,

                    "path":
                        str(
                            plugin_dir.relative_to(
                                ROOT
                            )
                        ),

                    "analysis":
                        analysis,

                    "offline":
                        True,

                    "activation":
                        "review-required",
                },
            )

        # ====================================================================
        # NOT FOUND
        # ====================================================================

        return json_response(
            self,
            {
                "error":
                    "not found",
            },
            404,
        )


# ============================================================================
# SERVER ENTRYPOINT
# ============================================================================

def main():

    import argparse

    parser = argparse.ArgumentParser(
        description=
            "ULPF production-MVP web console"
    )

    parser.add_argument(
        "--host",
        default=os.environ.get(
            "ULPF_WEB_HOST",
            "0.0.0.0",
        ),
    )

    parser.add_argument(
        "--port",
        type=int,
        default=int(
            os.environ.get(
                "ULPF_WEB_PORT",
                "5173",
            )
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # LOCAL-FIRST INITIALIZATION
    # ------------------------------------------------------------------------

    init_app()

    start_live_runtime()

    # ------------------------------------------------------------------------
    # SERVER
    # ------------------------------------------------------------------------

    class ULPFHTTPServer(
        ThreadingHTTPServer
    ):
        allow_reuse_address = True
        daemon_threads = True

    server = ULPFHTTPServer(
        (
            args.host,
            args.port,
        ),
        Handler,
    )

    # ------------------------------------------------------------------------
    # TLS
    # ------------------------------------------------------------------------

    cert = os.environ.get(
        "ULPF_TLS_CERT"
    )

    key = os.environ.get(
        "ULPF_TLS_KEY"
    )

    ca = os.environ.get(
        "ULPF_TLS_CA"
    )

    if bool(cert) != bool(key):

        raise SystemExit(
            "ULPF_TLS_CERT and "
            "ULPF_TLS_KEY must be "
            "configured together"
        )

    if cert and key:

        ctx = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH
        )

        ctx.load_cert_chain(
            cert,
            key,
        )

        if ca:

            ctx.load_verify_locations(
                cafile=ca
            )

            if _env_true(
                "ULPF_TLS_REQUIRE_CLIENT_CERT",
                False,
            ):

                ctx.verify_mode = (
                    ssl.CERT_REQUIRED
                )

        server.socket = (
            ctx.wrap_socket(
                server.socket,
                server_side=True,
            )
        )

        print(
            f"[ULPF] Web console: "
            f"https://{args.host}:"
            f"{args.port}"
        )

    else:

        print(
            f"[ULPF] Web console: "
            f"http://{args.host}:"
            f"{args.port}"
        )

    print(
        "[ULPF] Local storage: "
        + str(DATA_DIR)
    )

    print(
        "[ULPF] PostgreSQL: "
        + (
            "ENABLED"
            if POSTGRES_ENABLED
            else "DISABLED / LOCAL FALLBACK"
        )
    )

    # ------------------------------------------------------------------------
    # SERVE
    # ------------------------------------------------------------------------

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\n[ULPF] Shutdown requested."
        )

    finally:

        _runtime_stop.set()

        try:
            server.shutdown()
        except Exception:
            pass

        try:
            server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
