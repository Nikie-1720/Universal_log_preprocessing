"""
ULPF Parser Registry
====================

Central registry for:

1. Built-in format parsers
2. YAML/config-driven vendor parsers
3. Runtime parser reload
4. Safe parser selection
5. One-level chained parsing
6. Parser/plugin validation support

Selection algorithm
-------------------
1. Every registered parser scores the raw line using match() -> 0..1.
2. YAML parser specs additionally evaluate their match conditions.
3. A matching YAML parser gets preference over a generic parser.
4. If no parser reaches the minimum threshold, format detection is used.
5. The selected parser parses the raw record.
6. If a parser exposes sub_raw (for example a syslog payload), the
   payload is parsed once more using a suitable parser.
7. Parser failures NEVER discard the original raw event. PlainParser
   is used as a lossless fallback.

Runtime reload
--------------
The registry can be rebuilt atomically with reload().
This allows an approved ULPF plugin to become active without restarting
the whole application.
"""

from __future__ import annotations

import re
from typing import Any

from ulpf import detection
from ulpf.parsers import (
    BUILTIN_CLASSES,
    BUILTIN_PRIORITIES,
    ParseResult,
    Parser,
    PlainParser,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_MATCH_SCORE = 0.5

# Small preference added to a parser whose YAML match conditions pass.
SPEC_MATCH_BONUS = 0.01

# Maximum additional confidence awarded by YAML match conditions.
SPEC_MATCH_CAP = 0.06


# ---------------------------------------------------------------------------
# Parser specification
# ---------------------------------------------------------------------------

class ParserSpec:
    """
    A YAML-defined parser configuration.

    Example:

        id: demo-unknown-fw
        format: kv
        priority: 80

        match:
          any:
            - contains: "TIME="

        mapping:
          event_time: {src: TIME, type: timestamp}
    """

    def __init__(self, cfg: dict):
        if not isinstance(cfg, dict):
            raise TypeError("Parser configuration must be a dictionary")

        self.cfg = cfg

        self.id = str(
            cfg.get("id")
            or cfg.get("name")
            or "unnamed"
        ).strip()

        self.name = str(
            cfg.get("name")
            or self.id
        ).strip()

        self.vendor = cfg.get("vendor")
        self.product = cfg.get("product")

        self.version = str(
            cfg.get("version")
            or "1.0.0"
        )

        try:
            self.priority = int(cfg.get("priority", 50))
        except (TypeError, ValueError):
            self.priority = 50

        self.match = cfg.get("match")

        self.format = str(
            cfg.get("format", "regex")
        ).strip().lower()

        self.options = cfg.get("format_options") or {}

    def __repr__(self) -> str:
        return f"<ParserSpec {self.id} ({self.format})>"

    def to_dict(self) -> dict:
        """Return the original configuration."""
        return dict(self.cfg)


# ---------------------------------------------------------------------------
# Match condition helpers
# ---------------------------------------------------------------------------

def _eval_condition(cond: dict, raw: str) -> bool:
    """
    Evaluate one parser match condition.

    Supported operators:

        contains
        not_contains
        startswith
        endswith
        equals
        regex
    """

    if not isinstance(cond, dict) or not cond:
        return False

    try:
        op, value = next(iter(cond.items()))
    except StopIteration:
        return False

    value = str(value)

    try:
        if op == "contains":
            return value in raw

        if op == "not_contains":
            return value not in raw

        if op == "startswith":
            return raw.strip().startswith(value)

        if op == "endswith":
            return raw.strip().endswith(value)

        if op == "equals":
            return raw.strip() == value

        if op == "regex":
            return re.search(value, raw) is not None

    except (re.error, TypeError, ValueError):
        return False

    return False


def _eval_conditions(conds: list, raw: str) -> int:
    """
    Evaluate a list of conditions.

    Returns:
        Number of matched conditions.
    """

    if not isinstance(conds, list):
        return 0

    matched = 0

    for cond in conds:
        if _eval_condition(cond, raw):
            matched += 1

    return matched


def spec_match_score(spec: ParserSpec, raw: str) -> float:
    """
    Calculate the YAML parser-spec match score.

    Returns:
        0.0 when the spec does not match.
        ~0.90-0.96 when the spec matches.

    This intentionally keeps YAML matching strong enough to beat
    generic format parsers while still allowing parser.match() to
    participate in the selection.
    """

    match = spec.match

    # No explicit match condition means the parser is intentionally
    # generic/configured for the format.
    if not match:
        return 0.90

    if not isinstance(match, dict):
        return 0.0

    # ---------------------------------------------------------------
    # ANY
    # ---------------------------------------------------------------

    if "any" in match:
        conditions = match.get("any") or []

        if not isinstance(conditions, list):
            return 0.0

        matched = _eval_conditions(conditions, raw)

        if matched <= 0:
            return 0.0

        return 0.90 + min(
            SPEC_MATCH_CAP,
            SPEC_MATCH_BONUS * matched,
        )

    # ---------------------------------------------------------------
    # ALL
    # ---------------------------------------------------------------

    conditions = match.get("all") or []

    if conditions:
        if not isinstance(conditions, list):
            return 0.0

        matched = _eval_conditions(conditions, raw)

        if matched == len(conditions):
            return 0.90 + min(
                SPEC_MATCH_CAP,
                SPEC_MATCH_BONUS * matched,
            )

        return 0.0

    # Unknown/empty match structure.
    return 0.0


# ---------------------------------------------------------------------------
# Parser Registry
# ---------------------------------------------------------------------------

class ParserRegistry:
    """
    Registry containing built-in and configuration-driven parsers.

    Important property:
        reload() builds a completely new parser list first and then
        swaps self.entries in one assignment.

    This avoids leaving the registry half-reloaded if a parser config
    is invalid.
    """

    def __init__(self, specs: list[dict] | None = None):
        self.entries: list[dict[str, Any]] = []
        self.reload(specs or [])

    # ------------------------------------------------------------------
    # Registry construction
    # ------------------------------------------------------------------

    def _build_entries(
        self,
        specs: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Build a complete parser registry without modifying the
        currently active registry.

        This makes reload() transactional from the registry's point
        of view.
        """

        new_entries: list[dict[str, Any]] = []

        # --------------------------------------------------------------
        # Built-in parsers
        # --------------------------------------------------------------

        for fmt, cls in BUILTIN_CLASSES.items():
            priority = BUILTIN_PRIORITIES.get(fmt, 10)

            try:
                parser_instance = cls()
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to initialize built-in parser '{fmt}': "
                    f"{exc}"
                ) from exc

            new_entries.append(
                {
                    "kind": "builtin",
                    "priority": priority,
                    "parser": parser_instance,
                    "spec": None,
                }
            )

        # --------------------------------------------------------------
        # YAML/config-driven parsers
        # --------------------------------------------------------------

        seen_ids: set[str] = set()

        for cfg in specs or []:
            if not isinstance(cfg, dict):
                raise ValueError(
                    "Parser specification must be a dictionary"
                )

            spec = ParserSpec(cfg)

            if not spec.id:
                raise ValueError(
                    "Parser specification has an empty id"
                )

            if spec.id in seen_ids:
                raise ValueError(
                    f"Duplicate parser specification id: {spec.id}"
                )

            seen_ids.add(spec.id)

            fmt = spec.format

            # Unknown format falls back to regex, preserving the
            # existing behavior.
            if fmt not in BUILTIN_CLASSES:
                fmt = "regex"

            parser_class = BUILTIN_CLASSES[fmt]

            try:
                parser_instance = parser_class(spec.options)
            except Exception as exc:
                raise ValueError(
                    f"Failed to initialize parser '{spec.id}' "
                    f"using format '{fmt}': {exc}"
                ) from exc

            new_entries.append(
                {
                    "kind": "spec",
                    "priority": spec.priority,
                    "parser": parser_instance,
                    "spec": spec,
                }
            )

        # Highest priority first.
        #
        # Stable sorting is intentional: if score and priority are
        # equal, earlier registrations retain deterministic behavior.
        new_entries.sort(
            key=lambda entry: -entry["priority"]
        )

        return new_entries

    def reload(
        self,
        specs: list[dict] | None = None,
    ) -> dict:
        """
        Atomically rebuild the registry.

        This is used when an approved plugin is activated.

        Example:

            result = registry.reload(load_parser_specs(cfg))

        Returns metadata useful for diagnostics/UI.
        """

        new_entries = self._build_entries(specs or [])

        # Atomic reference replacement.
        #
        # Do NOT clear self.entries and append into it. A running
        # pipeline could observe a partially rebuilt registry.
        self.entries = new_entries

        return {
            "ok": True,
            "parser_count": len(new_entries),
            "builtin_count": sum(
                1
                for entry in new_entries
                if entry["kind"] == "builtin"
            ),
            "spec_count": sum(
                1
                for entry in new_entries
                if entry["kind"] == "spec"
            ),
            "parser_ids": [
                self._entry_id(entry)
                for entry in new_entries
            ],
        }

    # ------------------------------------------------------------------
    # Parser registration
    # ------------------------------------------------------------------

    def add_spec(self, cfg: dict) -> ParserSpec:
        """
        Add a parser spec at runtime.

        For production plugin activation, reload() is preferred because
        it gives transactional registry replacement.
        """

        spec = ParserSpec(cfg)

        existing_ids = {
            self._entry_id(entry)
            for entry in self.entries
            if entry["kind"] == "spec"
        }

        if spec.id in existing_ids:
            raise ValueError(
                f"Parser specification already registered: {spec.id}"
            )

        fmt = spec.format

        if fmt not in BUILTIN_CLASSES:
            fmt = "regex"

        parser_class = BUILTIN_CLASSES[fmt]

        parser_instance = parser_class(spec.options)

        new_entries = list(self.entries)

        new_entries.append(
            {
                "kind": "spec",
                "priority": spec.priority,
                "parser": parser_instance,
                "spec": spec,
            }
        )

        new_entries.sort(
            key=lambda entry: -entry["priority"]
        )

        # Atomic replacement.
        self.entries = new_entries

        return spec

    # ------------------------------------------------------------------
    # Registry inspection
    # ------------------------------------------------------------------

    @staticmethod
    def _entry_id(entry: dict) -> str:
        """
        Get a stable parser identifier.
        """

        spec = entry.get("spec")

        if spec is not None:
            return spec.id

        parser = entry.get("parser")

        return str(
            getattr(parser, "id", None)
            or getattr(parser, "format_name", None)
            or parser.__class__.__name__
        )

    def list_parsers(self) -> list[dict]:
        """
        Return registry metadata for diagnostics/UI.
        """

        result = []

        for entry in self.entries:
            parser = entry["parser"]
            spec = entry["spec"]

            item = {
                "id": self._entry_id(entry),
                "kind": entry["kind"],
                "priority": entry["priority"],
                "format": getattr(
                    parser,
                    "format_name",
                    None,
                ),
            }

            if spec is not None:
                item.update(
                    {
                        "name": spec.name,
                        "vendor": spec.vendor,
                        "product": spec.product,
                        "version": spec.version,
                    }
                )

            result.append(item)

        return result

    def get_spec(self, parser_id: str) -> ParserSpec | None:
        """
        Find a YAML parser specification by ID.
        """

        parser_id = str(parser_id).strip()

        for entry in self.entries:
            spec = entry.get("spec")

            if spec is not None and spec.id == parser_id:
                return spec

        return None

    # ------------------------------------------------------------------
    # Parser selection
    # ------------------------------------------------------------------

    def _select(
        self,
        raw: str,
        exclude: type | None = None,
    ):
        """
        Select the best parser for a raw record.

        Returns:
            (parser, spec)

        or:

            (None, None)
        """

        if not isinstance(raw, str):
            raw = str(raw)

        best_key = None
        best = None

        # Snapshot the list reference.

        entries = self.entries

        for entry in entries:
            parser = entry["parser"]

            # Used by syslog chaining to avoid selecting the same
            # envelope parser again.
            if (
                exclude is not None
                and isinstance(parser, exclude)
            ):
                continue

            # ----------------------------------------------------------
            # Base parser score
            # ----------------------------------------------------------

            try:
                score = float(parser.match(raw))
            except Exception:
                score = 0.0

            if score < 0:
                score = 0.0

            if score > 1:
                score = 1.0

            # ----------------------------------------------------------
            # YAML specification matching
            # ----------------------------------------------------------

            spec = entry["spec"]

            if entry["kind"] == "spec":

                cond_score = spec_match_score(
                    spec,
                    raw,
                )

                # The explicit YAML match must pass.
                if cond_score <= 0:
                    continue

                # A matching config-driven parser should win over
                # a generic format parser.
                score = max(
                    score + SPEC_MATCH_BONUS,
                    cond_score,
                )

            if score <= 0:
                continue

            key = (
                score,
                entry["priority"],
            )

            if (
                best_key is None
                or key > best_key
            ):
                best_key = key
                best = (
                    parser,
                    spec,
                )

        # --------------------------------------------------------------
        # Minimum confidence threshold
        # --------------------------------------------------------------

        if (
            best is None
            or best_key is None
            or best_key[0] < MIN_MATCH_SCORE
        ):
            return None, None

        return best

    # ------------------------------------------------------------------
    # Format fallback
    # ------------------------------------------------------------------

    def _fallback(self, raw: str):
        """
        Use deterministic format detection when registry matching
        cannot confidently select a parser.
        """

        det = detection.detect_format(raw)

        fmt = det.get("format")

        parser_class = BUILTIN_CLASSES.get(fmt)

        if parser_class is None:
            parser_class = PlainParser

        try:
            parser = parser_class()
        except Exception:
            parser = PlainParser()

        return parser, None, det

    # ------------------------------------------------------------------
    # Safe parsing
    # ------------------------------------------------------------------

    def _safe_parse(
        self,
        parser: Parser,
        raw: str,
    ) -> ParseResult:
        """
        Parse without allowing parser exceptions to lose data.

        If a vendor parser fails, PlainParser receives the original
        raw record and the warning is attached to the result.
        """

        try:
            return parser.parse(raw)

        except Exception as exc:

            result = PlainParser().parse(raw)

            parser_id = getattr(
                parser,
                "id",
                parser.__class__.__name__,
            )

            result.warnings.append(
                f"parser {parser_id} error: "
                f"{exc.__class__.__name__}: {exc}"
            )

            return result

    # ------------------------------------------------------------------
    # Full parser chain
    # ------------------------------------------------------------------

    def parse_chain(self, raw: str):
        """
        Parse a raw record with automatic parser selection and
        one-level chaining.

        Returns:

            (
                result,
                parser,
                spec,
                detection,
                chained_parser_ids
            )
        """

        if not isinstance(raw, str):
            raw = str(raw)

        # --------------------------------------------------------------
        # First parser selection
        # --------------------------------------------------------------

        parser, spec = self._select(raw)

        det = None

        # --------------------------------------------------------------
        # Deterministic fallback
        # --------------------------------------------------------------

        if parser is None:
            parser, spec, det = self._fallback(raw)

        # --------------------------------------------------------------
        # Safe parse
        # --------------------------------------------------------------

        result = self._safe_parse(
            parser,
            raw,
        )

        chained: list[str] = []

        # --------------------------------------------------------------
        # One-level payload chaining
        # --------------------------------------------------------------

        sub_raw = getattr(
            result,
            "sub_raw",
            None,
        )

        if (
            sub_raw
            and isinstance(sub_raw, str)
            and sub_raw.strip()
        ):
            sub_parser, sub_spec = self._select(
                sub_raw,
                exclude=SyslogEnvelope,
            )

            if sub_parser is None:
                (
                    sub_parser,
                    sub_spec,
                    _
                ) = self._fallback(sub_raw)

            sub_result = self._safe_parse(
                sub_parser,
                sub_raw,
            )

            if (
                getattr(sub_result, "attributes", None)
                or getattr(sub_result, "message", None)
            ):
                result.merge(sub_result)

                chained.append(
                    getattr(
                        sub_parser,
                        "id",
                        sub_parser.__class__.__name__,
                    )
                )

                # If the inner parser is a configured parser,
                # it becomes the effective parser specification.
                if sub_spec is not None:
                    spec = sub_spec

        return (
            result,
            parser,
            spec,
            det,
            chained,
        )

    # ------------------------------------------------------------------
    # Parser validation
    # ------------------------------------------------------------------

    def validate_parser(
        self,
        parser_id: str,
        sample_raw: str,
    ) -> dict:
        """
        Validate an already registered parser against a sample event.

        This performs an actual parser-selection + parse operation,
        rather than merely checking whether YAML exists.

        This is useful for the plugin approval workflow.
        """

        parser_id = str(parser_id).strip()

        if not sample_raw or not sample_raw.strip():
            return {
                "ok": False,
                "parser_id": parser_id,
                "error": "sample_raw is empty",
            }

        target_entry = None

        for entry in self.entries:
            if (
                entry["kind"] == "spec"
                and entry["spec"] is not None
                and entry["spec"].id == parser_id
            ):
                target_entry = entry
                break

        if target_entry is None:
            return {
                "ok": False,
                "parser_id": parser_id,
                "error": "parser not found in registry",
            }

        parser = target_entry["parser"]
        spec = target_entry["spec"]

        # --------------------------------------------------------------
        # Check explicit match
        # --------------------------------------------------------------

        match_score = spec_match_score(
            spec,
            sample_raw,
        )

        if match_score <= 0:
            return {
                "ok": False,
                "parser_id": parser_id,
                "error": "parser match conditions did not match sample",
                "match_score": match_score,
            }

        # --------------------------------------------------------------
        # Parse directly with target parser.
        #
        # We deliberately do not call parse_chain() here because
        # validation must prove that THIS parser can process the
        # sample, rather than allowing another parser to succeed.
        # --------------------------------------------------------------

        try:
            result = parser.parse(sample_raw)

        except Exception as exc:
            return {
                "ok": False,
                "parser_id": parser_id,
                "error": (
                    f"parser raised "
                    f"{exc.__class__.__name__}: {exc}"
                ),
                "match_score": match_score,
            }

        attributes = getattr(
            result,
            "attributes",
            {},
        ) or {}

        message = getattr(
            result,
            "message",
            None,
        )

        warnings = list(
            getattr(
                result,
                "warnings",
                [],
            ) or []
        )

        # A parser that produces neither attributes nor message is
        # not useful enough to approve automatically.
        if not attributes and not message:
            return {
                "ok": False,
                "parser_id": parser_id,
                "error": "parser produced no attributes or message",
                "match_score": match_score,
                "warnings": warnings,
            }

        return {
            "ok": True,
            "parser_id": parser_id,
            "parser_name": spec.name,
            "vendor": spec.vendor,
            "product": spec.product,
            "format": spec.format,
            "priority": spec.priority,
            "match_score": round(match_score, 4),
            "attribute_count": len(attributes),
            "attributes": attributes,
            "message": message,
            "warnings": warnings,
        }


# ---------------------------------------------------------------------------
# Syslog envelope marker
# ---------------------------------------------------------------------------

class SyslogEnvelope(Parser):
    """
    Marker used to prevent syslog-in-syslog chaining loops.

    This class is intentionally not registered as a normal parser.
    It is only used as an exclusion marker when parsing nested
    syslog payloads.
    """

    id = "syslog-envelope"
    format_name = "envelope"