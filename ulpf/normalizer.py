"""Normalizer: turns parsed records into Universal Event Schema (UES) events.

Responsibilities:
  * build the UES envelope with guaranteed lossless `raw` preservation,
  * apply YAML mapping DSL (src/template + typed conversion + value maps),
  * apply taxonomy maps, severity maps, derived rules and constants,
  * auto-infer canonical fields from well-known raw keys,
  * record warnings (never drop data - worst case a field stays unmapped).
"""
from __future__ import annotations

import ipaddress
import re

from ulpf.schema import (
    UES_VERSION,
    SYSLOG_PRI_LABELS as SCHEMA_SYSLOG_PRI_LABELS,
    severity_label_and_number,
)
from ulpf.taxonomy import ACTION_SYNONYMS, INFERENCE_BY_KEY
from ulpf.utils import (
    iso,
    new_id,
    now_iso,
    parse_timestamp,
    safe_format,
    set_u,
    sha256_hex,
    get_u,
)


class _ConversionError(ValueError):
    pass


def convert_value(value, ctype: str | None, options: dict | None = None):
    """Convert a raw field value to a canonical typed value. Raises _ConversionError."""
    options = options or {}
    if value is None:
        return None
    if ctype in (None, "", "str"):
        if isinstance(value, (dict, list)):
            return value
        return str(value)

    s = str(value).strip()

    try:
        if ctype == "int" or ctype == "port":
            return int(float(s)) if "." in s else int(s)

        if ctype == "float" or ctype == "duration":
            return float(s)

        if ctype == "bool":
            return s.lower() in ("true", "yes", "1", "on", "enabled")

        if ctype == "ip":
            return str(ipaddress.ip_address(s))

        if ctype == "proto":
            if s.isdigit():
                return {
                    6: "tcp",
                    17: "udp",
                    1: "icmp",
                    47: "gre",
                    132: "sctp",
                }.get(int(s), s).lower()
            return s.lower()

        if ctype in ("epoch", "timestamp", "ts", "datetime"):
            dt = parse_timestamp(value)
            if dt is None:
                raise _ConversionError(f"unparseable timestamp: {value!r}")
            return iso(dt)

        if ctype == "bytes":
            return int(float(s))

        if ctype == "lower":
            return s.lower()

        if ctype == "upper":
            return s.upper()

        if ctype == "action":
            low = s.lower()
            return ACTION_SYNONYMS.get(low, low)

        if ctype == "loglevel":
            label, number = severity_label_and_number(s)
            if label is None:
                raise _ConversionError(f"unknown level: {value!r}")
            return label

        if ctype == "map":
            m = options.get("map") or {}
            return m.get(s, m.get(s.lower(), s))

        if ctype == "int_or_none":
            return int(s) if s.isdigit() else None

    except _ConversionError:
        raise
    except (ValueError, TypeError) as ex:
        raise _ConversionError(
            f"cannot convert {value!r} to {ctype}: {ex}"
        ) from ex

    return s


class Normalizer:
    def __init__(
        self,
        pipeline_id: str = "ulpf-core",
        pipeline_version: str = "1.0.0",
    ):
        self.pipeline_id = pipeline_id
        self.pipeline_version = pipeline_version

    # ---------------------------------------------------------------- main API
    def normalize(
        self,
        raw: str,
        source_meta: dict,
        result,
        parser,
        spec,
        det,
        chained,
    ) -> dict:
        now = now_iso()
        event = {"raw": raw}

        ues = event["ues"] = {
            "schema_version": UES_VERSION,
            "event_id": new_id(),
            "ingest_time": now,
            "tags": [],
            "labels": {},
        }

        meta = event["meta"] = {
            "pipeline_id": self.pipeline_id,
            "pipeline_version": self.pipeline_version,
            "parser": spec.id if spec else parser.id,
            "format": parser.format_name,
            "parse_status": "parsed",
            "warnings": list(result.warnings),
            "received_time": source_meta.get("received_time", now),
        }

        if source_meta.get("source_type"):
            meta["source_type"] = source_meta["source_type"]

        if source_meta.get("address"):
            meta["source_address"] = source_meta["address"]

        if source_meta.get("transport"):
            meta["source_transport"] = source_meta["transport"]

        if det:
            meta["detection"] = det

        if chained:
            meta["parser_chain"] = chained

        trace = event["trace"] = {
            "trace_id": new_id(),
            "raw_hash": sha256_hex(raw),
            "raw_size": len(raw.encode("utf-8", errors="replace")),
            "algorithm": "sha256",
            "lineage": [],
        }

        if source_meta.get("offset") is not None:
            trace["raw_offset"] = source_meta["offset"]

        attrs = dict(result.attributes)
        attr_lc = {str(k).lower(): v for k, v in attrs.items()}
        warnings: list[str] = meta["warnings"]

        def attr_get(name: str):
            return attr_lc.get(str(name).lower())

        envelope_src = {
            "_raw": raw,
            "_host": result.host,
            "_pri": result.pri,
            "_time": result.event_time,
        }

        # 1) YAML mapping DSL
        if spec is not None and spec.cfg.get("mapping"):
            for target, m in spec.cfg["mapping"].items():
                self._apply_mapping(
                    event,
                    target,
                    m or {},
                    attr_get,
                    attrs,
                    envelope_src,
                    warnings,
                )

        # 2) Taxonomy maps
        if spec is not None and spec.cfg.get("taxonomy"):
            for field, t in spec.cfg["taxonomy"].items():
                self._apply_taxonomy(
                    event,
                    field,
                    t or {},
                    attr_get,
                    warnings,
                )

        # 3) Severity block
        if spec is not None and spec.cfg.get("severity"):
            self._apply_severity(
                event,
                spec.cfg["severity"],
                attr_get,
            )

        # 4) Derived rules (regex on message -> set fields)
        for rule in (spec.cfg.get("derived") or []) if spec is not None else []:
            self._apply_derived(
                event,
                rule or {},
                attr_get,
                attrs,
                raw,
                warnings,
            )

        # 5) Constants
        for path, val in (
            (spec.cfg.get("constants") or {})
            if spec is not None
            else {}
        ).items():
            set_u(event, str(path), val)

        # 6) Parser envelope fallbacks
        if get_u(event, "event_time") is None and result.event_time is not None:
            dt = parse_timestamp(result.event_time)
            if dt is not None:
                set_u(event, "event_time", iso(dt))

        if get_u(event, "device.host") is None and result.host:
            set_u(event, "device.host", result.host)

        # RFC 5424/3164 PRI labels must come from the schema taxonomy,
        # not the normalized severity buckets used by ulpf.taxonomy.
        if (
            get_u(event, "severity") is None
            and result.pri is not None
            and 0 <= result.pri < 192
        ):
            label = SCHEMA_SYSLOG_PRI_LABELS[result.pri % 8]
            set_u(event, "severity_label", label)
            set_u(event, "severity", severity_label_and_number(label)[1])

        if get_u(event, "message") is None and result.message:
            set_u(event, "message", result.message)

        hints = result.hints or {}

        if get_u(event, "device.vendor") is None and hints.get("vendor"):
            set_u(event, "device.vendor", hints["vendor"])

        if get_u(event, "device.product") is None and hints.get("product"):
            set_u(event, "device.product", hints["product"])

        if get_u(event, "service") is None and hints.get("service"):
            set_u(event, "service", hints["service"])

        if (
            get_u(event, "severity_label") is None
            and hints.get("severity_raw") is not None
        ):
            label, number = severity_label_and_number(hints["severity_raw"])
            if label:
                set_u(event, "severity_label", label)
                set_u(event, "severity", number)

        # 7) Auto-inference from well-known raw keys
        self._infer(event, attr_lc)

        # 8) Defaults
        ues.setdefault("event_kind", "event")

        if ues.get("severity") is None:
            ues["severity"] = 10

        if ues.get("severity_label") is None:
            ues["severity_label"] = "info"

        if ues.get("event_time") is None:
            set_u(event, "event_time", ues["ingest_time"])
            warnings.append("event_time missing; defaulted to ingest time")

        dt = parse_timestamp(ues["event_time"])
        if dt is not None:
            ues["event_time_epoch_ms"] = int(dt.timestamp() * 1000)

        return event

    # ------------------------------------------------------------- sub-appliers
    def _apply_mapping(
        self,
        event,
        target,
        m,
        attr_get,
        attrs,
        envelope_src,
        warnings,
    ):
        try:
            if "template" in m:
                value = safe_format(str(m["template"]), attrs)
            elif "value" in m:
                value = m["value"]
            elif m.get("src") in envelope_src:
                value = envelope_src[m["src"]]
            else:
                value = attr_get(m.get("src", ""))

            if value is None or value == "":
                return

            value = convert_value(value, m.get("type"), m)

            if "map" in m and isinstance(value, str):
                value = m["map"].get(
                    value,
                    m["map"].get(value.lower(), value),
                )

            set_u(event, str(target), value)

            original_field = str(m.get("src") or "template")

            if "template" in m:
                original_field = (
                    " + ".join(
                        re.findall(
                            r"{([^}]+)}",
                            str(m["template"]),
                        )
                    )
                    or "template"
                )

            original_value = (
                value
                if original_field == "template"
                else (
                    attrs.get(str(m.get("src")))
                    if m.get("src") in attrs
                    else attr_get(str(m.get("src", "")))
                )
            )

            event["trace"]["lineage"].append({
                "normalized_field": str(target),
                "normalized_value": value,
                "original_field": original_field,
                "original_value": original_value,
                "mapping_rule": f"{original_field} -> {target}",
                "extraction_method": m.get(
                    "method",
                    "parser-field mapping",
                ),
                "confidence": float(m.get("confidence", 1.0)),
                "parser": event["meta"].get("parser"),
                "raw_hash": event["trace"]["raw_hash"],
            })

        except _ConversionError as ex:
            warnings.append(f"{target}: {ex}")

        except Exception as ex:  # pragma: no cover
            warnings.append(
                f"{target}: mapping error "
                f"{ex.__class__.__name__}: {ex}"
            )

    def _apply_taxonomy(
        self,
        event,
        field,
        t,
        attr_get,
        warnings,
    ):
        try:
            value = (
                attr_get(t.get("src", ""))
                if t.get("src")
                else None
            )

            if value is None or value == "":
                return

            if "map" in t:
                m = t["map"]
                value = m.get(
                    value,
                    m.get(str(value).lower(), value),
                )

            set_u(event, str(field), value)

            event["trace"]["lineage"].append({
                "normalized_field": str(field),
                "normalized_value": value,
                "original_field": str(t.get("src") or field),
                "original_value": attr_get(t.get("src", "")),
                "mapping_rule": f"{t.get('src', field)} -> {field}",
                "extraction_method": "taxonomy mapping",
                "confidence": float(t.get("confidence", 1.0)),
                "parser": event["meta"].get("parser"),
                "raw_hash": event["trace"]["raw_hash"],
            })

        except Exception as ex:  # pragma: no cover
            warnings.append(f"taxonomy {field}: {ex}")

    def _apply_severity(self, event, sev, attr_get):
        src = sev.get("src")
        value = attr_get(src) if src else None

        if value is None:
            return

        if "map" in sev:
            m = sev["map"]
            value = m.get(
                value,
                m.get(
                    str(value).lower(),
                    sev.get("default", value),
                ),
            )

        label, number = severity_label_and_number(value)

        if label:
            set_u(event, "severity_label", label)
            set_u(event, "severity", number)

    def _apply_derived(
        self,
        event,
        rule,
        attr_get,
        attrs,
        raw,
        warnings,
    ):
        try:
            pattern = rule.get("when")

            if not pattern:
                return

            field = rule.get("field", "message")

            text = (
                get_u(event, field)
                if field != "raw"
                else raw
            )

            if field == "message" and not text:
                text = raw

            # Regex input must be text. This keeps derived rules robust
            # when a mapped field is numeric or another scalar type.
            if text is None:
                text = ""
            elif not isinstance(text, str):
                text = str(text)

            match = re.search(str(pattern), text)

            if not match:
                return

            groups = {
                k: v
                for k, v in (match.groupdict() or {}).items()
                if v is not None
            }

            # Apply every derived field independently and record lineage
            # for each field.
            for target, sv in (rule.get("set") or {}).items():
                if isinstance(sv, dict):
                    if "value" in sv:
                        value = groups.get(sv["value"])
                    else:
                        value = sv.get("const")

                    options = sv
                    ctype = sv.get("type")
                else:
                    value = sv
                    options = {}
                    ctype = None

                if value is None:
                    continue

                value = convert_value(
                    value,
                    ctype,
                    options,
                )

                set_u(
                    event,
                    str(target),
                    value,
                )

                event["trace"]["lineage"].append({
                    "normalized_field": str(target),
                    "normalized_value": value,
                    "original_field": str(field),
                    "original_value": text,
                    "mapping_rule": f"{field} -> {target}",
                    "extraction_method": "derived regex",
                    "confidence": float(
                        rule.get("confidence", 1.0)
                    ),
                    "parser": event["meta"].get("parser"),
                    "raw_hash": event["trace"]["raw_hash"],
                })

        except _ConversionError as ex:
            warnings.append(f"derived: {ex}")

        except Exception as ex:  # pragma: no cover
            warnings.append(
                f"derived rule error: "
                f"{ex.__class__.__name__}: {ex}"
            )

    def _infer(self, event, attr_lc):
        for key, value in attr_lc.items():
            hit = INFERENCE_BY_KEY.get(key)

            if hit is None:
                continue

            target, ctype = hit

            if get_u(event, target) is not None:
                continue

            if value in (None, "", "-"):
                continue

            try:
                converted = convert_value(
                    value,
                    ctype,
                )
            except _ConversionError:
                continue

            if converted in (None, ""):
                continue

            set_u(
                event,
                target,
                converted,
            )

            event["trace"]["lineage"].append({
                "normalized_field": target,
                "normalized_value": converted,
                "original_field": key,
                "original_value": value,
                "mapping_rule": f"{key} -> {target}",
                "extraction_method": "offline key inference",
                "confidence": 0.78,
                "parser": event["meta"].get("parser"),
                "raw_hash": event["trace"]["raw_hash"],
            })

            if target == "severity_label":
                set_u(
                    event,
                    "severity",
                    severity_label_and_number(converted)[1],
                )

    # ----------------------------------------------------------- failure event
    def failure_event(
        self,
        raw: str,
        source_meta: dict,
        det,
        error: str,
    ) -> dict:
        now = now_iso()
        event = {"raw": raw}

        event["ues"] = {
            "schema_version": UES_VERSION,
            "event_id": new_id(),
            "ingest_time": now,
            "event_kind": "event",
            "event_time": now,
            "tags": [],
            "labels": {},
            "severity": 10,
            "severity_label": "info",
        }

        event["meta"] = {
            "pipeline_id": self.pipeline_id,
            "pipeline_version": self.pipeline_version,
            "parser": "none",
            "format": (det or {}).get("format", "unknown"),
            "parse_status": "failed",
            "warnings": [
                f"normalization error: {error}"
            ],
            "received_time": source_meta.get("received_time", now),
        }

        event["trace"] = {
            "trace_id": new_id(),
            "raw_hash": sha256_hex(raw),
            "raw_size": len(
                raw.encode(
                    "utf-8",
                    errors="replace",
                )
            ),
            "algorithm": "sha256",
            "lineage": [],
        }

        if source_meta.get("source_type"):
            event["meta"]["source_type"] = source_meta["source_type"]
        if source_meta.get("address"):
            event["meta"]["source_address"] = source_meta["address"]
        if source_meta.get("transport"):
            event["meta"]["source_transport"] = source_meta["transport"]

        return event
