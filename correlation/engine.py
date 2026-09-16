"""ULPF stateful correlation engine.

Purpose
-------
Turn individually normalized security events into explainable multi-event
detections. The engine is deliberately deterministic and lightweight so it can
run in an air-gapped deployment without an external SIEM or LLM.

Correlation patterns
--------------------
1. Brute-force followed by successful authentication
2. Successful authentication followed by privilege escalation
3. Multi-stage intrusion chain
4. Repeated security failures from same source (NEW)
5. Distributed auth failures across users (NEW)

The engine uses a bounded in-memory sliding window. PostgreSQL remains the
system of record for generated alerts; this module does not require a new DB
table, so it can be introduced without a schema migration.
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any


class CorrelationEngine:
    def __init__(
        self,
        *,
        window_seconds: int = 900,
        brute_force_window: int = 300,
        max_events_per_key: int = 200,
        cooldown_seconds: int = 600,
        group_window_seconds: int = 300,
        group_threshold: int = 3,
    ):
        self.window_seconds = window_seconds
        self.brute_force_window = brute_force_window
        self.max_events_per_key = max_events_per_key
        self.cooldown_seconds = cooldown_seconds

        # Grouping parameters (NEW)
        self.group_window_seconds = group_window_seconds
        self.group_threshold = group_threshold

        self._by_source: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=max_events_per_key)
        )
        self._by_user: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=max_events_per_key)
        )
        # NEW: track repeated failures by (rule, source) for grouping
        self._by_failure_key: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=max_events_per_key)
        )
        self._last_emitted: dict[str, float] = {}
        self._total_events = 0
        self._total_cases = 0

    @staticmethod
    def _now_epoch() -> float:
        return time.time()

    @staticmethod
    def _event_time(event: dict) -> float:
        ues = event.get("ues") or {}
        meta = event.get("meta") or {}

        for value in (
            ues.get("event_time"),
            ues.get("ingest_time"),
            meta.get("received_time"),
        ):
            if not value:
                continue

            try:
                text = str(value).replace("Z", "+00:00")
                dt = datetime.fromisoformat(text)

                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)

                return dt.timestamp()

            except (ValueError, TypeError):
                continue

        return CorrelationEngine._now_epoch()

    @staticmethod
    def _get(event: dict, *paths: str) -> Any:
        ues = event.get("ues") or {}

        for path in paths:
            cur = ues
            ok = True

            for part in path.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    ok = False
                    break

                cur = cur[part]

            if ok and cur not in (None, ""):
                return cur

        return None

    @classmethod
    def _source(cls, event: dict) -> str:
        return str(
            cls._get(
                event,
                "source.ip",
                "source.address",
                "client.ip",
                "network.client.ip",
            )
            or event.get("meta", {}).get("source_address")
            or ""
        ).strip()

    @classmethod
    def _user(cls, event: dict) -> str:
        return str(
            cls._get(event, "user.name", "user.id", "user")
            or ""
        ).strip()

    @classmethod
    def _action(cls, event: dict) -> str:
        return str(
            cls._get(event, "action", "event.action", "event.name")
            or ""
        ).lower().strip()

    @classmethod
    def _outcome(cls, event: dict) -> str:
        return str(
            cls._get(event, "outcome", "event.outcome")
            or ""
        ).lower().strip()

    @classmethod
    def _category(cls, event: dict) -> str:
        return str(
            cls._get(event, "category", "event.category", "event.type")
            or ""
        ).lower().strip()

    # NEW: destination port extraction for protocol-specific correlation
    @classmethod
    def _destination_port(cls, event: dict) -> int | None:
        value = cls._get(
            event,
            "destination.port",
            "network.destination.port",
            "destination_port",
        )

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _text(cls, event: dict) -> str:
        import json

        return json.dumps(
            event,
            ensure_ascii=False,
            default=str,
        ).lower()

    @classmethod
    def _is_auth_failure(cls, event: dict) -> bool:
        text = cls._text(event)
        outcome = cls._outcome(event)
        category = cls._category(event)

        return (
            (
                "auth" in category
                or "authentication" in text
                or "failed password" in text
                or "login failed" in text
                or "authentication failure" in text
                or "invalid user" in text
            )
            and (
                outcome in {"failure", "failed", "denied"}
                or "failed password" in text
                or "login failed" in text
                or "authentication failure" in text
                or "invalid user" in text
            )
        )

    @classmethod
    def _is_auth_success(cls, event: dict) -> bool:
        text = cls._text(event)
        outcome = cls._outcome(event)
        category = cls._category(event)
        action = cls._action(event)

        return (
            (
                "auth" in category
                or "authentication" in text
                or "login" in text
                or action in {
                    "login",
                    "authenticate",
                    "authentication",
                }
            )
            and (
                outcome in {
                    "success",
                    "successful",
                    "succeeded",
                    "allowed",
                }
                or "accepted password" in text
                or "login successful" in text
                or "logged in" in text
            )
            and not cls._is_auth_failure(event)
        )

    @classmethod
    def _is_privilege_escalation(cls, event: dict) -> bool:
        text = cls._text(event)
        action = cls._action(event)
        category = cls._category(event)

        terms = (
            "privilege escalation",
            "privilege_escalation",
            "sudo",
            "setuid",
            "role changed",
            "role_change",
            "admin granted",
            "administrator",
            "root access",
            "elevated",
            "permission changed",
            "useradd",
            "usermod",
        )

        return (
            any(term in text for term in terms)
            or action in {
                "privilege-escalation",
                "privilege_escalation",
                "elevate",
                "sudo",
                "role-change",
            }
            or category in {
                "privilege",
                "privilege_escalation",
                "iam",
            }
        )

    @classmethod
    def _is_discovery_or_scan(cls, event: dict) -> bool:
        text = cls._text(event)
        action = cls._action(event)
        category = cls._category(event)

        terms = (
            "port scan",
            "port_scan",
            "network scan",
            "network_scan",
            "recon",
            "discovery",
            "scan detected",
            "nmap",
            "masscan",
        )

        return (
            any(term in text for term in terms)
            or action in {
                "scan",
                "port-scan",
                "network-scan",
                "discovery",
            }
            or category in {
                "network_scan",
                "discovery",
                "recon",
            }
        )

    @classmethod
    def _is_security_failure(cls, event: dict) -> bool:
        """Detect generic denied/dropped/blocked actions."""
        action = cls._action(event)
        outcome = cls._outcome(event)
        return (
            action in {"deny", "drop", "blocked", "block", "reject", "failed"}
            or outcome in {"failure", "failed", "denied"}
        )

    @classmethod
    def _risk_for_case(cls, case_type: str, count: int = 0) -> int:
        if case_type == "brute-force-success":
            return min(96, 82 + max(0, count - 5) * 2)

        if case_type == "auth-privilege":
            return 92

        if case_type == "intrusion-chain":
            return 98

        if case_type == "repeated-failures":
            return min(85, 60 + max(0, count - 3) * 4)

        if case_type == "distributed-auth-failures":
            return 88

        # NEW: explicit SSH brute-force risk scoring
        if case_type == "ssh-brute-force":
            return min(95, 78 + max(0, count - 3) * 4)

        return 75

    @staticmethod
    def _severity_label(risk: int) -> str:
        if risk >= 95:
            return "critical"

        if risk >= 80:
            return "high"

        if risk >= 60:
            return "medium"

        return "low"

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds

        for store in (
            self._by_source,
            self._by_user,
            self._by_failure_key,
        ):
            empty = []

            for key, events in store.items():
                while events and events[0]["ts"] < cutoff:
                    events.popleft()

                if not events:
                    empty.append(key)

            for key in empty:
                store.pop(key, None)

        for key, ts in list(self._last_emitted.items()):
            if now - ts > self.cooldown_seconds * 3:
                self._last_emitted.pop(key, None)

    def _cooldown(self, fingerprint: str, now: float) -> bool:
        previous = self._last_emitted.get(fingerprint, 0)

        if now - previous < self.cooldown_seconds:
            return False

        self._last_emitted[fingerprint] = now
        return True

    @staticmethod
    def _trace_ids(events: list[dict]) -> list[str]:
        ids = []

        for event in events:
            trace_id = (event.get("trace") or {}).get("trace_id")

            if trace_id:
                ids.append(str(trace_id))

        return ids

    def _make_case(
        self,
        *,
        case_type: str,
        title: str,
        description: str,
        evidence: list[dict],
        source_ip: str = "",
        user: str = "",
        risk: int,
        now: float,
        extra: dict | None = None,
    ) -> dict:
        trace_ids = self._trace_ids(evidence)

        fingerprint_source = "|".join(
            [
                case_type,
                source_ip,
                user,
                *trace_ids,
            ]
        )

        correlation_id = "COR-" + hashlib.sha256(
            fingerprint_source.encode("utf-8")
        ).hexdigest()[:16]

        timestamps = [
            e["ts"]
            for e in evidence
            if e.get("ts") is not None
        ]

        first_ts = min(timestamps) if timestamps else now
        last_ts = max(timestamps) if timestamps else now

        # Build per-event evidence with readable timestamps
        evidence_items = []

        for e in evidence:
            ev_time = (e.get("ues") or {}).get("event_time")

            evidence_items.append({
                "trace_id": (e.get("trace") or {}).get("trace_id"),
                "event_time": ev_time,
                "event_time_display": self._format_time(ev_time),
                "parser": (e.get("meta") or {}).get("parser"),
                "source_type": (e.get("meta") or {}).get("source_type"),
                "action": self._action(e),
                "outcome": self._outcome(e),
                "category": self._category(e),
                "severity": (e.get("ues") or {}).get("severity"),
                "raw_hash": (e.get("trace") or {}).get("raw_hash"),
            })

        result = {
            "correlation_id": correlation_id,
            "created_at": datetime.fromtimestamp(
                now,
                tz=timezone.utc,
            ).isoformat(),
            "first_seen": datetime.fromtimestamp(
                first_ts,
                tz=timezone.utc,
            ).isoformat(),
            "last_seen": datetime.fromtimestamp(
                last_ts,
                tz=timezone.utc,
            ).isoformat(),
            "first_seen_display": self._format_ts(first_ts),
            "last_seen_display": self._format_ts(last_ts),
            "duration_seconds": int(last_ts - first_ts),
            "rule_id": f"correlation-{case_type}",
            "type": case_type,
            "title": title,
            "description": description,
            "risk_score": risk,
            "severity": self._severity_label(risk),
            "source_ip": source_ip or None,
            "user": user or None,
            "event_count": len(evidence),
            "trace_ids": trace_ids,
            "evidence": evidence_items,
            "explanation": {
                "engine": "ULPF Stateful Correlation Engine v1",
                "window_seconds": self.window_seconds,
                "why": description,
                "rule": case_type,
            },
        }

        if extra:
            result.update(extra)

        return result

    @staticmethod
    def _format_time(value) -> str:
        if not value:
            return "—"

        try:
            text = str(value).replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt.astimezone(timezone.utc).strftime(
                "%H:%M:%S UTC"
            )

        except (ValueError, TypeError):
            return str(value)[:19]

    @staticmethod
    def _format_ts(epoch: float) -> str:
        try:
            return datetime.fromtimestamp(
                epoch,
                tz=timezone.utc,
            ).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

        except (ValueError, OSError, OverflowError):
            return "—"

    def _case_to_alert(self, case: dict) -> dict:
        evidence = case.get("evidence") or []

        raw_hashes = [
            item.get("raw_hash")
            for item in evidence
            if item.get("raw_hash")
        ]

        return {
            "alert_id": case["correlation_id"],
            "created_at": case["created_at"],
            "rule": case["rule_id"],
            "rule_id": case["rule_id"],
            "title": case["title"],
            "description": case["description"],
            "severity": case["severity"],
            "reason": case["description"],
            "trace_id": (case.get("trace_ids") or [None])[-1],
            "source_ip": case.get("source_ip"),
            "user": case.get("user"),
            "raw_hash": raw_hashes[-1] if raw_hashes else None,
            "raw_hashes": raw_hashes,
            "acknowledged": False,
            "correlation_id": case["correlation_id"],
            "risk_score": case["risk_score"],
            "correlation_type": case["type"],
            "evidence_trace_ids": case["trace_ids"],
            "event_count": case["event_count"],
            "first_seen": case.get("first_seen"),
            "last_seen": case.get("last_seen"),
            "duration_seconds": case.get("duration_seconds", 0),
            "explanation": case["explanation"],
        }

    def ingest(self, event: dict) -> dict:
        now = self._event_time(event)
        wall_now = self._now_epoch()

        self._total_events += 1
        self._prune(wall_now)

        source = self._source(event)
        user = self._user(event)

        record = {
            "event": event,
            "ts": now,
        }

        if source:
            self._by_source[source].append(record)

        if user:
            self._by_user[user].append(record)

        # Track security failures per (source, action) for grouping
        if source and self._is_security_failure(event):
            failure_key = f"{source}:{self._action(event) or 'failure'}"
            self._by_failure_key[failure_key].append(record)

        cases = []
        alerts = []

        source_events = (
            list(self._by_source.get(source, ()))
            if source
            else []
        )

        recent = [
            r
            for r in source_events
            if now - r["ts"] <= self.window_seconds
        ]

        # ─────────────────────────────────────────────────────────────
        # Pattern 0: Repeated auth failures (activity group only, no alert)
        # ─────────────────────────────────────────────────────────────
        if self._is_auth_failure(event) and source:
            failures = [
                r["event"]
                for r in recent
                if self._is_auth_failure(r["event"])
                and 0 <= now - r["ts"] <= self.brute_force_window
            ]

            if len(failures) >= 5:
                evidence = failures[-5:]

                fp = f"brute-force-failures:{source}"

                if self._cooldown(fp, wall_now):
                    case = self._make_case(
                        case_type="brute-force-failures",
                        title="Repeated failed logins detected",
                        description=(
                            f"{len(failures)} failed authentication "
                            f"attempts from {source} were observed "
                            "within 5 minutes."
                        ),
                        evidence=evidence,
                        source_ip=source,
                        user=user,
                        risk=self._risk_for_case(
                            "brute-force-success",
                            len(failures),
                        ),
                        now=wall_now,
                    )
                    cases.append(case)

        # ─────────────────────────────────────────────────────────────
        # Pattern 0b: Repeated security failures (NEW - grouping)
        # Groups N+ denied/blocked events from same source into ONE case
        # ─────────────────────────────────────────────────────────────
        if (
            self._is_security_failure(event)
            and source
            and not self._is_auth_failure(event)
        ):
            action = self._action(event) or "failure"
            failure_key = f"{source}:{action}"

            all_failures = list(
                self._by_failure_key.get(
                    failure_key,
                    (),
                )
            )

            recent_failures = [
                r
                for r in all_failures
                if 0 <= now - r["ts"] <= self.group_window_seconds
            ]

            if len(recent_failures) >= self.group_threshold:
                evidence = [
                    r["event"]
                    for r in recent_failures[-20:]
                ]

                fp = (
                    f"repeated-failures:"
                    f"{source}:"
                    f"{action}"
                )

                if self._cooldown(fp, wall_now):
                    case = self._make_case(
                        case_type="repeated-failures",
                        title=f"Repeated {action} events from {source}",
                        description=(
                            f"{len(recent_failures)} {action} events "
                            f"observed from {source} in the last "
                            f"{self.group_window_seconds // 60} minutes."
                        ),
                        evidence=evidence,
                        source_ip=source,
                        user=user,
                        risk=self._risk_for_case(
                            "repeated-failures",
                            len(recent_failures),
                        ),
                        now=wall_now,
                        extra={
                            "group_action": action,
                            "group_count": len(recent_failures),
                        },
                    )
                    cases.append(case)

        # ─────────────────────────────────────────────────────────────
        # Pattern 0c: Repeated SSH denial / brute-force activity
        # Explicit perimeter SSH detection for port 22/2222.
        # ─────────────────────────────────────────────────────────────
        if self._is_security_failure(event) and source:
            destination_port = self._destination_port(event)

            if destination_port in {22, 2222}:
                ssh_failures = [
                    r
                    for r in recent
                    if self._is_security_failure(r["event"])
                    and self._destination_port(r["event"]) in {22, 2222}
                    and 0 <= now - r["ts"] <= self.group_window_seconds
                ]

                if len(ssh_failures) >= self.group_threshold:
                    evidence = [
                        r["event"]
                        for r in ssh_failures[-20:]
                    ]

                    fp = (
                        f"ssh-brute-force:"
                        f"{source}:"
                        f"{destination_port}"
                    )

                    if self._cooldown(fp, wall_now):
                        ssh_count = len(ssh_failures)

                        case = self._make_case(
                            case_type="ssh-brute-force",
                            title="Repeated denied SSH activity detected",
                            description=(
                                f"{ssh_count} denied SSH connection "
                                f"attempts from {source} to port "
                                f"{destination_port} were observed "
                                f"within "
                                f"{self.group_window_seconds // 60} "
                                "minutes."
                            ),
                            evidence=evidence,
                            source_ip=source,
                            user=user,
                            risk=min(
                                95,
                                78 + max(0, ssh_count - 3) * 4,
                            ),
                            now=wall_now,
                            extra={
                                "group_action": "ssh-deny",
                                "group_count": ssh_count,
                                "destination_port": destination_port,
                                "attack_type": "ssh_brute_force",
                            },
                        )

                        cases.append(case)
                        alerts.append(
                            self._case_to_alert(case)
                        )

        # ─────────────────────────────────────────────────────────────
        # Pattern 1: Brute-force followed by successful login
        # ─────────────────────────────────────────────────────────────
        if self._is_auth_success(event) and source:
            failures = [
                r["event"]
                for r in recent[:-1]
                if self._is_auth_failure(r["event"])
                and now - r["ts"] <= self.brute_force_window
            ]

            if len(failures) >= 5:
                evidence = failures[-5:] + [event]

                risk = self._risk_for_case(
                    "brute-force-success",
                    len(failures),
                )

                fp = f"brute-force-success:{source}"

                if self._cooldown(fp, wall_now):
                    case = self._make_case(
                        case_type="brute-force-success",
                        title="Brute-force attack followed by successful login",
                        description=(
                            f"{len(failures)} authentication failures "
                            f"from {source} were followed by a "
                            "successful authentication within 5 minutes."
                        ),
                        evidence=evidence,
                        source_ip=source,
                        user=user,
                        risk=risk,
                        now=wall_now,
                    )
                    cases.append(case)
                    alerts.append(
                        self._case_to_alert(case)
                    )

        # ─────────────────────────────────────────────────────────────
        # Pattern 2: Successful auth followed by privilege escalation
        # ─────────────────────────────────────────────────────────────
        if self._is_privilege_escalation(event) and source:
            successes = [
                r["event"]
                for r in recent[:-1]
                if self._is_auth_success(r["event"])
                and 0 <= now - r["ts"] <= self.window_seconds
            ]

            if successes:
                evidence = [successes[-1], event]

                fp = f"auth-privilege:{source}:{user or 'unknown'}"

                if self._cooldown(fp, wall_now):
                    case = self._make_case(
                        case_type="auth-privilege",
                        title="Authentication followed by privilege escalation",
                        description=(
                            f"A successful authentication from "
                            f"{source} was followed by a "
                            "privilege-sensitive action."
                        ),
                        evidence=evidence,
                        source_ip=source,
                        user=user,
                        risk=self._risk_for_case("auth-privilege"),
                        now=wall_now,
                    )
                    cases.append(case)
                    alerts.append(
                        self._case_to_alert(case)
                    )

        # ─────────────────────────────────────────────────────────────
        # Pattern 3: Multi-stage intrusion chain
        # ─────────────────────────────────────────────────────────────
        if self._is_privilege_escalation(event) and source:
            scans = [
                r["event"]
                for r in recent[:-1]
                if self._is_discovery_or_scan(r["event"])
            ]

            successes = [
                r["event"]
                for r in recent[:-1]
                if self._is_auth_success(r["event"])
            ]

            failures = [
                r["event"]
                for r in recent[:-1]
                if self._is_auth_failure(r["event"])
            ]

            if scans and successes and failures:
                ordered = []

                for r in recent:
                    ev = r["event"]

                    if (
                        self._is_discovery_or_scan(ev)
                        or self._is_auth_failure(ev)
                        or self._is_auth_success(ev)
                        or self._is_privilege_escalation(ev)
                    ):
                        ordered.append(ev)

                evidence = ordered[-10:]

                fp = f"intrusion-chain:{source}:{user or 'unknown'}"

                if self._cooldown(fp, wall_now):
                    case = self._make_case(
                        case_type="intrusion-chain",
                        title="Multi-stage intrusion chain detected",
                        description=(
                            f"Observed discovery/scan activity, "
                            f"authentication failures, successful "
                            f"login and privilege-sensitive action "
                            f"associated with {source}."
                        ),
                        evidence=evidence,
                        source_ip=source,
                        user=user,
                        risk=self._risk_for_case("intrusion-chain"),
                        now=wall_now,
                    )
                    cases.append(case)
                    alerts.append(
                        self._case_to_alert(case)
                    )

        self._total_cases += len(cases)

        return {
            "cases": cases,
            "alerts": alerts,
        }

    def stats(self) -> dict:
        return {
            "version": "1.1.0",
            "window_seconds": self.window_seconds,
            "group_window_seconds": self.group_window_seconds,
            "group_threshold": self.group_threshold,
            "tracked_sources": len(self._by_source),
            "tracked_users": len(self._by_user),
            "tracked_failure_keys": len(self._by_failure_key),
            "events_seen": self._total_events,
            "cases_generated": self._total_cases,
        }