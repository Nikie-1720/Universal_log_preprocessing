"""
PostgreSQL persistence layer for ULPF.

Schema-aware PostgreSQL repository.

This implementation is designed for ULPF deployments where the database
schema may evolve between versions.

Features:
    - Detects actual PostgreSQL columns at runtime.
    - Inserts only columns that exist.
    - Generates placeholders dynamically.
    - Prevents placeholder/parameter mismatches.
    - Normalizes alert severity to integer values.
    - Guarantees a non-null rule_id for alerts.
    - Supports optional agent columns.
    - Preserves raw evidence.
    - Preserves field-level lineage.
    - Supports:
          StorageRepository(db)
      and:
          StorageRepository(database=db)
    - Supports optional RawStore integration.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from psycopg.types.json import Jsonb


# =============================================================
# HELPERS
# =============================================================

def _json(value: Any) -> Jsonb:
    """
    Convert a Python value into PostgreSQL JSONB.

    None is converted to an empty object so JSONB columns receive
    a valid JSON value.
    """
    if value is None:
        value = {}

    return Jsonb(value)


def _dt(value: Any):
    """
    Convert a value into a timezone-aware datetime.

    Accepted examples:
        datetime object
        ISO timestamp
        ISO timestamp ending in Z
    """
    if not value:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (TypeError, ValueError):
        return None


def _get(
    data: dict,
    path: str,
    default=None,
):
    """
    Read a nested dictionary value using dot notation.

    Example:
        _get(event, "device.vendor")
    """
    current = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return default

        current = current.get(part)

    return default if current is None else current


def _severity_int(value: Any) -> int:
    """
    Normalize severity to an integer in the range 0-100.
    """

    if value is None:
        return 0

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, (int, float)):
        return max(
            0,
            min(100, int(value)),
        )

    text = str(value).strip().lower()

    mapping = {
        "critical": 100,
        "crit": 100,
        "severe": 90,
        "high": 80,
        "medium": 60,
        "moderate": 60,
        "low": 30,
        "info": 10,
        "informational": 10,
        "unknown": 0,
    }

    if text in mapping:
        return mapping[text]

    try:
        return max(
            0,
            min(
                100,
                int(float(text)),
            ),
        )

    except (TypeError, ValueError):
        return 0


def _severity_label(value: Any) -> str:
    """
    Normalize severity into a readable label.
    """

    if isinstance(value, str):
        text = value.strip().lower()

        if text:
            return text

    number = _severity_int(value)

    if number >= 90:
        return "critical"

    if number >= 70:
        return "high"

    if number >= 40:
        return "medium"

    if number > 0:
        return "low"

    return "info"


# =============================================================
# REPOSITORY
# =============================================================

class StorageRepository:
    """
    PostgreSQL persistence repository for ULPF.

    Supported:

        StorageRepository(db)

    and:

        StorageRepository(database=db)

    Optional:

        StorageRepository(
            database=db,
            raw_store=raw_store,
        )
    """

    def __init__(
        self,
        db=None,
        raw_store=None,
        database=None,
    ):
        self.db = database or db

        if self.db is None:
            raise ValueError(
                "StorageRepository requires a database instance"
            )

        self.raw_store = raw_store

        # Cache actual PostgreSQL table columns.
        self._column_cache: dict[str, set[str]] = {}

    # =========================================================
    # SCHEMA INTROSPECTION
    # =========================================================

    def _columns(
        self,
        table: str,
    ) -> set[str]:
        """
        Return the actual columns available in a PostgreSQL table.

        This makes the repository tolerant of schema revisions.
        """

        cached = self._column_cache.get(table)

        if cached is not None:
            return cached

        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = %s
                """,
                (table,),
            ).fetchall()

        columns = {
            str(row[0])
            for row in rows
        }

        self._column_cache[table] = columns

        return columns

    def _clear_column_cache(self):
        """
        Clear cached schema metadata.
        """
        self._column_cache.clear()

    def _filter_values(
        self,
        table: str,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Keep only fields that actually exist in the PostgreSQL table.
        """

        columns = self._columns(table)

        return {
            key: value
            for key, value in values.items()
            if key in columns
        }

    # =========================================================
    # GENERIC INSERT
    # =========================================================

    def _insert(
        self,
        conn,
        table: str,
        values: dict[str, Any],
        *,
        conflict_column: str | None = None,
        update_columns: Iterable[str] | None = None,
    ):
        """
        Schema-aware INSERT.

        Placeholder count is generated directly from the final
        filtered values.

        This prevents errors such as:

            27 placeholders but 26 parameters

        """

        values = self._filter_values(
            table,
            values,
        )

        if not values:
            raise RuntimeError(
                f"No compatible columns found for table '{table}'"
            )

        columns = list(values.keys())

        params = tuple(
            values[column]
            for column in columns
        )

        column_sql = ", ".join(
            columns
        )

        placeholders = ", ".join(
            ["%s"] * len(columns)
        )

        sql = f"""
            INSERT INTO {table} (
                {column_sql}
            )
            VALUES (
                {placeholders}
            )
        """

        # -----------------------------------------------------
        # Optional ON CONFLICT handling
        # -----------------------------------------------------

        if conflict_column:
            available = self._columns(table)

            if conflict_column in available:

                updates = list(
                    update_columns
                    or columns
                )

                updates = [
                    column
                    for column in updates
                    if column in available
                    and column != conflict_column
                ]

                if updates:

                    update_sql = ", ".join(
                        f"{column} = EXCLUDED.{column}"
                        for column in updates
                    )

                    sql += f"""
                        ON CONFLICT ({conflict_column})
                        DO UPDATE SET
                            {update_sql}
                    """

                else:

                    sql += f"""
                        ON CONFLICT ({conflict_column})
                        DO NOTHING
                    """

        conn.execute(
            sql,
            params,
        )

    # =========================================================
    # EVENTS
    # =========================================================

    def save_event(
        self,
        event: dict,
        *,
        raw: str | None = None,
    ) -> dict:
        """
        Persist a normalized ULPF event.

        Also persists:

            - raw evidence
            - lineage
        """

        if not isinstance(event, dict):
            raise TypeError(
                "event must be a dictionary"
            )

        trace = event.get("trace") or {}
        ues = event.get("ues") or {}
        meta = event.get("meta") or {}

        trace_id = str(
            trace.get("trace_id")
            or ues.get("event_id")
            or uuid.uuid4()
        )

        event_id = str(
            ues.get("event_id")
            or trace_id
        )

        # -----------------------------------------------------
        # Raw payload
        # -----------------------------------------------------

        if raw is None:
            raw = event.get("raw")

        if raw is None:
            raw = ""

        raw = str(raw)

        raw_hash = (
            trace.get("raw_hash")
            or self._sha256(raw)
        )

        raw_size = int(
            trace.get("raw_size")
            or len(
                raw.encode(
                    "utf-8",
                    errors="replace",
                )
            )
        )

        raw_event_id = (
            f"RAW-{raw_hash[:20]}"
        )

        raw_path = ""

        # -----------------------------------------------------
        # Optional raw store
        # -----------------------------------------------------

        if self.raw_store:

            try:

                raw_info = self.raw_store.put(
                    raw,
                    trace_id=trace_id,
                    source_type=str(
                        meta.get(
                            "source_type"
                        )
                        or "unknown"
                    ),
                    received_time=meta.get(
                        "received_time"
                    ),
                )

                if raw_info:

                    raw_hash = (
                        raw_info.get(
                            "raw_hash"
                        )
                        or raw_hash
                    )

                    raw_size = int(
                        raw_info.get(
                            "raw_size"
                        )
                        or raw_size
                    )

                    raw_path = (
                        raw_info.get(
                            "raw_path"
                        )
                        or ""
                    )

                    raw_event_id = (
                        raw_info.get(
                            "raw_event_id"
                        )
                        or raw_event_id
                    )

            except Exception as exc:

                print(
                    "[ULPF] Raw store warning:",
                    exc,
                )

        now = datetime.now(
            timezone.utc
        )

        severity = _severity_int(
            ues.get("severity")
            or meta.get("severity")
        )

        severity_label = (
            ues.get("severity_label")
            or meta.get("severity_label")
            or _severity_label(severity)
        )

        # -----------------------------------------------------
        # EVENT
        # -----------------------------------------------------

        event_values = {

            "trace_id": trace_id,

            "event_id": event_id,
            "idempotency_key": (
                meta.get("idempotency_key")
                or meta.get("agent_fingerprint")
            ),

            "event_time": _dt(
                ues.get(
                    "event_time"
                )
            ),

            "ingest_time": _dt(
                ues.get(
                    "ingest_time"
                )
            ) or now,

            "received_time": _dt(
                meta.get(
                    "received_time"
                )
            ),

            "source_type": (
                meta.get(
                    "source_type"
                )
            ),

            "source_address": (
                meta.get(
                    "source_address"
                )
                or meta.get(
                    "source_ip"
                )
                or _get(
                    ues,
                    "source.ip"
                )
            ),

            "source_transport": (
                meta.get(
                    "source_transport"
                )
                or _get(
                    ues,
                    "network.transport"
                )
            ),
            "transport": (
                meta.get(
                    "source_transport"
                )
                or meta.get(
                    "transport"
                )
                or _get(
                    ues,
                    "network.transport"
                )
            ),

            "parser": (
                meta.get(
                    "parser"
                )
            ),

            "parser_version": (
                meta.get(
                    "parser_version"
                )
            ),

            "pipeline_id": (
                meta.get(
                    "pipeline_id"
                )
            ),

            "pipeline_version": (
                meta.get(
                    "pipeline_version"
                )
            ),

            "format": (
                meta.get(
                    "format"
                )
            ),

            "parse_status": (
                meta.get(
                    "parse_status"
                )
                or "success"
            ),

            "severity": severity,

            "severity_label": severity_label,

            "vendor": (
                _get(
                    ues,
                    "device.vendor"
                )
                or meta.get(
                    "vendor"
                )
            ),

            "product": (
                _get(
                    ues,
                    "device.product"
                )
                or meta.get(
                    "product"
                )
            ),

            "agent_id": (
                meta.get(
                    "agent_id"
                )
            ),

            "raw_hash": raw_hash,

            "raw_size": raw_size,

            "raw_path": raw_path,

            "schema_version": (
                ues.get(
                    "schema_version"
                )
                or trace.get(
                    "schema_version"
                )
                or "1.0"
            ),

            "event_json": _json(
                event
            ),

            "meta_json": _json(
                meta
            ),

            "ues_json": _json(
                ues
            ),

            "updated_at": now,
        }

        with self.db.transaction() as conn:

            self._insert(
                conn,
                "events",
                event_values,
                conflict_column=(
                    "idempotency_key"
                    if event_values.get("idempotency_key")
                    else "trace_id"
                ),
                update_columns=[
                    "event_json",
                    "meta_json",
                    "ues_json",
                    "raw_hash",
                    "raw_size",
                    "raw_path",
                    "severity",
                    "severity_label",
                    "updated_at",
                ],
            )

            # -------------------------------------------------
            # RAW EVIDENCE
            # -------------------------------------------------

            raw_values = {

                "raw_event_id": raw_event_id,

                "trace_id": trace_id,

                "raw_hash": raw_hash,

                "sha256": raw_hash,

                "raw_size": raw_size,

                "raw_path": raw_path,

                "source": (
                    meta.get(
                        "source_type"
                    )
                    or meta.get(
                        "source"
                    )
                    or "unknown"
                ),

                "received_time": (
                    _dt(
                        meta.get(
                            "received_time"
                        )
                    )
                    or now
                ),
            }

            self._insert(
                conn,
                "raw_events",
                raw_values,
                conflict_column="raw_event_id",
                update_columns=[
                    "trace_id",
                    "raw_hash",
                    "sha256",
                    "raw_size",
                    "raw_path",
                    "source",
                    "received_time",
                ],
            )

            # -------------------------------------------------
            # LINEAGE
            # -------------------------------------------------

            lineage_columns = self._columns(
                "lineage"
            )

            if "trace_id" in lineage_columns:

                conn.execute(
                    """
                    DELETE FROM lineage
                    WHERE trace_id = %s
                    """,
                    (trace_id,),
                )

                lineage = (
                    trace.get(
                        "lineage"
                    )
                    or []
                )

                if isinstance(
                    lineage,
                    dict,
                ):

                    lineage = (
                        lineage.get(
                            "fields"
                        )
                        or []
                    )

                if not isinstance(
                    lineage,
                    list,
                ):

                    lineage = []

                for item in lineage:

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    confidence = item.get(
                        "confidence"
                    )

                    try:

                        if confidence is not None:
                            confidence = float(
                                confidence
                            )

                    except (
                        TypeError,
                        ValueError,
                    ):

                        confidence = None

                    lineage_values = {

                        "trace_id": trace_id,

                        "normalized_field": (
                            item.get(
                                "normalized_field"
                            )
                            or item.get(
                                "target"
                            )
                        ),

                        "normalized_value": _json(
                            item.get(
                                "normalized_value"
                            )
                        ),

                        "original_field": (
                            item.get(
                                "original_field"
                            )
                            or item.get(
                                "source"
                            )
                        ),

                        "original_value": _json(
                            item.get(
                                "original_value"
                            )
                        ),

                        "mapping_rule": (
                            item.get(
                                "mapping_rule"
                            )
                        ),

                        "extraction_method": (
                            item.get(
                                "extraction_method"
                            )
                        ),

                        "confidence": confidence,

                        "parser": (
                            item.get(
                                "parser"
                            )
                            or meta.get(
                                "parser"
                            )
                        ),

                        "raw_hash": (
                            item.get(
                                "raw_hash"
                            )
                            or raw_hash
                        ),
                    }

                    self._insert(
                        conn,
                        "lineage",
                        lineage_values,
                    )

        return {
            "trace_id": trace_id,
            "raw_event_id": raw_event_id,
            "raw_hash": raw_hash,
            "raw_size": raw_size,
            "raw_path": raw_path,
        }

    # =========================================================
    # ALERTS
    # =========================================================

    def save_alert(
        self,
        alert: dict,
    ):
        """
        Persist a ULPF security alert.

        Important:

        ULPF alert generation may use:

            rule

        while PostgreSQL expects:

            rule_id

        Therefore this method explicitly normalizes both.

        It also guarantees that rule_id is never NULL.
        """

        if not isinstance(alert, dict):
            raise TypeError(
                "alert must be a dictionary"
            )

        # -----------------------------------------------------
        # Alert ID
        # -----------------------------------------------------

        alert_id = str(
            alert.get(
                "alert_id"
            )
            or uuid.uuid4()
        )

        # -----------------------------------------------------
        # Embedded alert JSON
        # -----------------------------------------------------

        alert_payload = alert.get(
            "alert_json"
        )

        if not isinstance(
            alert_payload,
            dict,
        ):
            alert_payload = {}

        # -----------------------------------------------------
        # RULE ID
        #
        # Support all common ULPF representations:
        #
        #   rule_id
        #   rule
        #   alert_json.rule_id
        #   alert_json.rule
        #
        # Finally use unknown-rule so PostgreSQL NOT NULL
        # constraints can never fail.
        # -----------------------------------------------------

        rule_id = (
            alert.get(
                "rule_id"
            )
            or alert.get(
                "rule"
            )
            or alert_payload.get(
                "rule_id"
            )
            or alert_payload.get(
                "rule"
            )
            or "unknown-rule"
        )

        rule_id = str(
            rule_id
        ).strip()

        if not rule_id:
            rule_id = "unknown-rule"

        # -----------------------------------------------------
        # TRACE ID
        # -----------------------------------------------------

        trace_id = (
            alert.get(
                "trace_id"
            )
            or alert_payload.get(
                "trace_id"
            )
        )

        if trace_id is not None:
            trace_id = str(
                trace_id
            )

        # -----------------------------------------------------
        # SEVERITY
        # -----------------------------------------------------

        severity_raw = alert.get(
            "severity"
        )

        if severity_raw is None:
            severity_raw = alert_payload.get(
                "severity"
            )

        severity_value = _severity_int(
            severity_raw
        )

        severity_label = (
            alert.get(
                "severity_label"
            )
            or alert_payload.get(
                "severity_label"
            )
            or _severity_label(
                severity_raw
            )
        )

        # -----------------------------------------------------
        # TITLE
        # -----------------------------------------------------

        title = (
            alert.get(
                "title"
            )
            or alert_payload.get(
                "title"
            )
            or "ULPF Security Alert"
        )

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        description = (
            alert.get(
                "description"
            )
            or alert_payload.get(
                "description"
            )
            or ""
        )

        # -----------------------------------------------------
        # SOURCE / DESTINATION
        # -----------------------------------------------------

        source_ip = (
            alert.get(
                "source_ip"
            )
            or alert.get(
                "src_ip"
            )
            or alert_payload.get(
                "source_ip"
            )
            or alert_payload.get(
                "src_ip"
            )
        )

        destination_ip = (
            alert.get(
                "destination_ip"
            )
            or alert.get(
                "dst_ip"
            )
            or alert_payload.get(
                "destination_ip"
            )
            or alert_payload.get(
                "dst_ip"
            )
        )

        # -----------------------------------------------------
        # STATUS
        # -----------------------------------------------------

        status = (
            alert.get(
                "status"
            )
            or alert_payload.get(
                "status"
            )
            or "open"
        )
        if alert.get("acknowledged") is True:
            status = "acknowledged"

        now = datetime.now(timezone.utc)

        # -----------------------------------------------------
        # NORMALIZED ALERT JSON
        # -----------------------------------------------------

        normalized_alert = {
            **alert_payload,
            **alert,
            "alert_id": alert_id,
            "trace_id": trace_id,
            "rule_id": rule_id,
            "severity": severity_value,
            "severity_label": severity_label,
            "title": title,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "status": status,
            "acknowledged_at": (
                _dt(alert.get("acknowledged_at"))
                or (now if alert.get("acknowledged") is True else None)
            ),
        }

        # -----------------------------------------------------
        # ALERT VALUES
        # -----------------------------------------------------

        alert_values = {

            "alert_id": alert_id,

            "trace_id": trace_id,

            # CRITICAL:
            # Never allow this to become NULL.
            "rule_id": rule_id,

            "severity": severity_value,

            "severity_label": severity_label,

            "title": title,

            "description": description,

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "status": status,

            "acknowledged_at": (
                _dt(alert.get("acknowledged_at"))
                or (now if alert.get("acknowledged") is True else None)
            ),

            "alert_json": _json(
                normalized_alert
            ),

            "updated_at": now,
        }

        # -----------------------------------------------------
        # DATABASE INSERT
        # -----------------------------------------------------

        with self.db.transaction() as conn:

            self._insert(
                conn,
                "alerts",
                alert_values,
                conflict_column="alert_id",
                update_columns=[
                    "trace_id",
                    "rule_id",
                    "severity",
                    "severity_label",
                    "title",
                    "description",
                    "source_ip",
                    "destination_ip",
                    "status",
                    "acknowledged_at",
                    "alert_json",
                    "updated_at",
                ],
            )

        return alert_id

    # =========================================================
    # AGENTS
    # =========================================================

    def upsert_agent(
        self,
        agent: dict,
    ):
        """
        Register or update an endpoint collection agent.
        """

        if not isinstance(
            agent,
            dict,
        ):
            raise TypeError(
                "agent must be a dictionary"
            )

        now = datetime.now(
            timezone.utc
        )

        agent_id = (
            agent.get(
                "agent_id"
            )
            or agent.get(
                "id"
            )
        )

        if not agent_id:
            agent_id = str(
                uuid.uuid4()
            )

        agent_values = {

            "agent_id": agent_id,

            "name": (
                agent.get(
                    "name"
                )
                or agent.get(
                    "hostname"
                )
                or agent_id
            ),

            "hostname": (
                agent.get(
                    "hostname"
                )
            ),

            "os_name": (
                agent.get(
                    "os_name"
                )
                or agent.get(
                    "os"
                )
            ),

            "os_version": (
                agent.get(
                    "os_version"
                )
            ),

            "agent_version": (
                agent.get(
                    "agent_version"
                )
                or agent.get(
                    "version"
                )
            ),

            "status": (
                agent.get(
                    "status"
                )
                or "online"
            ),

            "last_seen": (
                _dt(
                    agent.get(
                        "last_seen"
                    )
                )
                or now
            ),

            "capabilities": _json(
                agent.get(
                    "capabilities"
                )
                or {}
            ),

            # Optional schema field.
            "config_json": _json(
                agent.get(
                    "config"
                )
                or agent.get(
                    "config_json"
                )
                or {}
            ),
            "config": _json(
                agent.get(
                    "config"
                )
                or agent.get(
                    "config_json"
                )
                or {}
            ),

            # Optional schema field.
            "metadata_json": _json(
                agent.get(
                    "metadata"
                )
                or agent.get(
                    "metadata_json"
                )
                or {}
            ),
            "metadata": _json(
                agent.get(
                    "metadata"
                )
                or agent.get(
                    "metadata_json"
                )
                or {}
            ),

            "updated_at": now,
        }

        with self.db.transaction() as conn:

            self._insert(
                conn,
                "agents",
                agent_values,
                conflict_column="agent_id",
                update_columns=[
                    "name",
                    "hostname",
                    "os_name",
                    "os_version",
                    "agent_version",
                    "status",
                    "last_seen",
                    "capabilities",
                    "config_json",
                    "metadata_json",
                    "updated_at",
                ],
            )

        return agent_id

    # =========================================================
    # PLUGINS
    # =========================================================

    def upsert_plugin(
        self,
        plugin: dict,
    ):
        """
        Register or update a parser plugin.
        """

        if not isinstance(
            plugin,
            dict,
        ):
            raise TypeError(
                "plugin must be a dictionary"
            )

        plugin_id = (
            plugin.get(
                "plugin_id"
            )
            or plugin.get(
                "id"
            )
            or str(
                uuid.uuid4()
            )
        )

        now = datetime.now(
            timezone.utc
        )

        plugin_values = {

            "plugin_id": plugin_id,

            "name": plugin.get(
                "name"
            ),

            "vendor": plugin.get(
                "vendor"
            ),

            "product": plugin.get(
                "product"
            ),

            "version": plugin.get(
                "version"
            ),

            "format": plugin.get(
                "format"
            ),

            "status": (
                plugin.get(
                    "status"
                )
                or "enabled"
            ),

            "parser": plugin.get(
                "parser"
            ),

            "manifest_json": _json(
                plugin
            ),
            "manifest": _json(plugin),

            "updated_at": now,
        }

        with self.db.transaction() as conn:

            self._insert(
                conn,
                "plugin_registry",
                plugin_values,
                conflict_column="plugin_id",
                update_columns=[
                    "name",
                    "vendor",
                    "product",
                    "version",
                    "format",
                    "status",
                    "parser",
                    "manifest_json",
                    "updated_at",
                ],
            )

        return plugin_id

    # =========================================================
    # READ EVENT
    # =========================================================

    def get_event(
        self,
        trace_id: str,
    ):
        """
        Retrieve a normalized event by trace ID.
        """

        columns = self._columns(
            "events"
        )

        if "event_json" not in columns:
            return None

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT event_json
                FROM events
                WHERE trace_id = %s
                """,
                (trace_id,),
            ).fetchone()

        if not row:
            return None

        return row[0]

    # =========================================================
    # READ EVENTS
    # =========================================================

    def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
    ):
        """
        Return recent normalized events.
        """

        limit = max(
            1,
            min(
                int(limit),
                1000,
            ),
        )
        offset = max(0, int(offset))

        columns = self._columns(
            "events"
        )

        if "event_json" not in columns:
            return []

        # Select a timestamp column that definitely exists.
        if "updated_at" in columns:
            order_column = "updated_at"

        elif "ingest_time" in columns:
            order_column = "ingest_time"

        elif "event_time" in columns:
            order_column = "event_time"

        else:
            order_column = "trace_id"

        with self.db.connect() as conn:

            rows = conn.execute(
                f"""
                SELECT event_json
                FROM events
                ORDER BY {order_column} DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            ).fetchall()

        return [
            row[0]
            for row in rows
        ]

    # =========================================================
    # READ LINEAGE
    # =========================================================

    def get_lineage(
        self,
        trace_id: str,
    ):
        """
        Retrieve field-level lineage.
        """

        columns = self._columns(
            "lineage"
        )

        requested = [

            "normalized_field",

            "normalized_value",

            "original_field",

            "original_value",

            "mapping_rule",

            "extraction_method",

            "confidence",

            "parser",

            "raw_hash",
        ]

        available = [
            column
            for column in requested
            if column in columns
        ]

        if not available:
            return []

        select_sql = ", ".join(
            available
        )

        if "id" in columns:
            order_sql = "ORDER BY id"

        else:
            order_sql = ""

        with self.db.connect() as conn:

            rows = conn.execute(
                f"""
                SELECT
                    {select_sql}
                FROM lineage
                WHERE trace_id = %s
                {order_sql}
                """,
                (trace_id,),
            ).fetchall()

        return [
            dict(
                zip(
                    available,
                    row,
                )
            )
            for row in rows
        ]

    # =========================================================
    # READ AGENTS
    # =========================================================

    def list_agents(
        self,
    ):
        """
        Return registered endpoint agents.
        """

        columns = self._columns(
            "agents"
        )

        preferred = [

            "agent_id",

            "name",

            "hostname",

            "os_name",

            "os_version",

            "agent_version",

            "status",

            "last_seen",

            "capabilities",

            "config_json",

            "metadata_json",
        ]

        available = [
            column
            for column in preferred
            if column in columns
        ]

        if not available:
            return []

        select_sql = ", ".join(
            available
        )

        if "last_seen" in columns:
            order_sql = "ORDER BY last_seen DESC"

        else:
            order_sql = ""

        with self.db.connect() as conn:

            rows = conn.execute(
                f"""
                SELECT
                    {select_sql}
                FROM agents
                {order_sql}
                """
            ).fetchall()

        return [
            dict(
                zip(
                    available,
                    row,
                )
            )
            for row in rows
        ]

    # =========================================================
    # READ ALERTS
    # =========================================================

    def list_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
    ):
        """
        Return recent security alerts.
        """

        limit = max(
            1,
            min(
                int(limit),
                1000,
            ),
        )
        offset = max(0, int(offset))

        columns = self._columns(
            "alerts"
        )

        if "alert_json" not in columns:
            return []

        if "created_at" in columns:
            order_column = "created_at"

        elif "updated_at" in columns:
            order_column = "updated_at"

        else:
            order_column = "alert_id"

        with self.db.connect() as conn:

            rows = conn.execute(
                f"""
                SELECT alert_json
                FROM alerts
                ORDER BY {order_column} DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            ).fetchall()

        return [
            row[0]
            for row in rows
        ]

    # =========================================================
    # CORRELATION CASES / FORENSICS
    # =========================================================

    def save_correlation(self, case: dict) -> str:
        """Persist a deterministic correlation case idempotently."""
        if not isinstance(case, dict):
            raise TypeError("case must be a dictionary")
        correlation_id = str(case.get("correlation_id") or "")
        if not correlation_id:
            raise ValueError("correlation_id is required")
        now = datetime.now(timezone.utc)
        values = {
            "correlation_id": correlation_id,
            "rule_id": str(case.get("rule_id") or case.get("rule") or "unknown-rule"),
            "case_type": str(case.get("type") or case.get("case_type") or "unknown"),
            "title": str(case.get("title") or "ULPF correlation case"),
            "description": case.get("description") or case.get("reason") or "",
            "severity": case.get("severity") or "info",
            "risk_score": _severity_int(case.get("risk_score")),
            "source_ip": case.get("source_ip"),
            "username": case.get("user") or case.get("username"),
            "event_count": int(case.get("event_count") or len(case.get("trace_ids") or [])),
            "first_seen": _dt(case.get("first_seen")),
            "last_seen": _dt(case.get("last_seen")),
            "trace_ids": _json(case.get("trace_ids") or case.get("evidence_trace_ids") or []),
            "evidence": _json(case.get("evidence") or []),
            "case_json": _json(case),
            "status": case.get("status") or "open",
            "updated_at": now,
        }
        with self.db.transaction() as conn:
            self._insert(
                conn, "correlation_cases", values,
                conflict_column="correlation_id",
                update_columns=[k for k in values if k not in {"correlation_id", "created_at"}],
            )
        return correlation_id

    def list_correlations(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        columns = self._columns("correlation_cases")
        if "case_json" not in columns:
            return []
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT case_json FROM correlation_cases "
                "ORDER BY COALESCE(last_seen, updated_at) DESC LIMIT %s",
                (limit,),
            ).fetchall()
        return [row[0] for row in rows]

    def verify_raw(self, trace_id: str, raw: str | None = None) -> dict | None:
        """Verify stored evidence against its recorded SHA-256 digest."""
        columns = self._columns("raw_events")
        if not {"raw_hash", "sha256", "raw_path"}.issubset(columns):
            return None
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT raw_hash, sha256, raw_path, raw_size "
                "FROM raw_events WHERE trace_id = %s ORDER BY created_at DESC LIMIT 1",
                (trace_id,),
            ).fetchone()
        if not row:
            return None
        recorded, sha256, path, size = row
        payload = raw
        if payload is None and path:
            try:
                with open(path, "rb") as handle:
                    payload = handle.read()
            except OSError:
                payload = None
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest() if payload is not None else None
        return {
            "trace_id": trace_id,
            "recorded_hash": recorded or sha256,
            "computed_hash": digest,
            "verified": bool(digest and digest == (recorded or sha256)),
            "raw_size": size,
            "raw_path": path,
        }

    def claim_agent_receipt(self, agent_id: str, fingerprint: str) -> bool:
        """Atomically claim an agent delivery fingerprint."""
        receipt_id = hashlib.sha256(
            f"{agent_id}:{fingerprint}".encode("utf-8")
        ).hexdigest()
        with self.db.transaction() as conn:
            columns = self._columns("agent_receipts")
            if not {"receipt_id", "agent_id", "fingerprint"}.issubset(columns):
                return True
            cur = conn.execute(
                "INSERT INTO agent_receipts(receipt_id, agent_id, fingerprint) "
                "VALUES (%s, %s, %s) ON CONFLICT (agent_id, fingerprint) DO NOTHING",
                (receipt_id, agent_id, fingerprint),
            )
            return bool(cur.rowcount)

    def export_events(self, limit: int = 1000) -> list[dict]:
        """Return a bounded forensic export from PostgreSQL."""
        return self.list_events(limit=max(1, min(int(limit), 10000)))

    # =========================================================
    # SCHEMA INFO
    # =========================================================

    def schema_info(self):
        """
        Return detected PostgreSQL columns.

        Useful for debugging and schema migration checks.
        """

        tables = [

            "events",

            "raw_events",

            "lineage",

            "alerts",

            "correlation_cases",

            "agents",

            "plugin_registry",
        ]

        return {
            table: sorted(
                self._columns(table)
            )
            for table in tables
        }

    # =========================================================
    # HASH
    # =========================================================

    @staticmethod
    def _sha256(
        raw: str,
    ) -> str:
        """
        Calculate SHA-256 hash of raw log evidence.
        """

        return hashlib.sha256(
            raw.encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()