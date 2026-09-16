"""ULPF command line interface."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from collections import Counter

from ulpf import __version__
from ulpf.config import load_pipeline_config, load_parser_specs
from ulpf.detection import detect_format
from ulpf.enricher import build_enrichers
from ulpf.outputs import StdoutOutput, build_outputs
from ulpf.parsers import BUILTIN_CLASSES
from ulpf.pipeline import Pipeline, Runtime
from ulpf.registry import ParserRegistry
from ulpf.schema import UES_SCHEMA, UES_VERSION
from ulpf.taxonomy import INFERENCE_BY_KEY
from ulpf.local_ai import analyze as local_ai_analyze
from ulpf.utils import (
    Ansi,
    colorize,
    iter_lines,
    json_dumps,
    parse_timestamp,
    now_iso,
    new_id,
    sha256_hex,
)

DEFAULT_BATCH = 500


def _c(args) -> Ansi:
    return colorize(
        not getattr(args, "no_color", False) and sys.stdout.isatty()
    )


def _build_pipeline(cfg: dict) -> Pipeline:
    specs = load_parser_specs(cfg)
    registry = ParserRegistry(specs)
    return Pipeline(
        cfg,
        registry=registry,
        enrichers=build_enrichers(cfg),
    )


# --------------------------------------------------------------------------- run
def cmd_run(args) -> int:
    cfg = load_pipeline_config(args.config)
    runtime = Runtime(cfg)
    stats = runtime.run_forever()
    print(json_dumps(stats, pretty=True), file=sys.stderr)
    return 0


# -------------------------------------------------------------------------- parse
def cmd_parse(args) -> int:
    c = _c(args)
    cfg = load_pipeline_config(args.config)
    pipeline = _build_pipeline(cfg)

    outputs: list = []

    if args.output:
        for spec in args.output:
            if spec == "stdout":
                outputs.append(
                    StdoutOutput({"pretty": args.pretty})
                )
            else:
                otype, _, value = spec.partition(":")
                options = (
                    {"type": otype, "path": value}
                    if value
                    else {"type": otype}
                )
                outputs.extend(build_outputs([options]))
    else:
        outputs = [StdoutOutput({"pretty": args.pretty})]

    for out in outputs:
        out.open()

    files = args.files if args.files else ["-"]

    total = 0
    shown = 0
    limit = args.limit if args.limit and args.limit > 0 else None
    started = time.time()
    batch: list[dict] = []

    def _flush():
        if batch:
            for out in outputs:
                out.write(batch)
            batch.clear()

    try:
        for file in files:
            if workers_requested(args) > 1:
                total += _parse_parallel(
                    args,
                    file,
                    pipeline,
                    outputs,
                )
                continue

            stream = (
                sys.stdin
                if file == "-"
                else iter_lines(file)
            )

            offset = 0

            for raw in stream:
                if not raw.strip():
                    continue

                meta = {
                    "source_type": "file",
                    "address": file,
                    "transport": "file",
                }

                if file != "-":
                    meta["offset"] = offset

                event = pipeline.process_raw(raw, meta)

                offset += (
                    len(
                        raw.encode(
                            "utf-8",
                            errors="replace",
                        )
                    )
                    + 1
                )

                total += 1
                batch.append(event)

                if limit is None or shown < limit:
                    if (
                        not args.output
                        or args.output == ["stdout"]
                    ):
                        _print_event(
                            event,
                            shown + 1,
                            c,
                            args,
                        )
                    shown += 1

                if len(batch) >= DEFAULT_BATCH:
                    _flush()

            if file != "-":
                _flush()

        _flush()

    finally:
        for out in outputs:
            out.flush()
            out.close()

    elapsed = max(time.time() - started, 1e-6)

    snap = pipeline.stats.snapshot()["counters"]

    print(
        f"{c.BOLD}ULPF parse summary{c.RESET}",
        file=sys.stderr,
    )

    print(
        f"  events: {total} "
        f"(parsed {snap.get('parsed', 0)}, "
        f"failed {snap.get('failed', 0)}) "
        f"in {elapsed:.2f}s "
        f"-> {total / elapsed:,.0f} ev/s",
        file=sys.stderr,
    )

    parsers = {
        k.split(":", 1)[1]: v
        for k, v in snap.items()
        if k.startswith("parser:")
    }

    print(
        "  parsers: "
        + ", ".join(
            f"{k}={v}"
            for k, v in sorted(parsers.items())
        )
        if parsers
        else "  parsers: -",
        file=sys.stderr,
    )

    print(
        f"  threat intel hits: "
        f"{snap.get('threat_hits', 0)}",
        file=sys.stderr,
    )

    return (
        0
        if snap.get("failed", 0) == 0
        else 1
    )


def workers_requested(args) -> int:
    return getattr(args, "workers", 1) or 1


def _parse_parallel(
    args,
    file,
    pipeline,
    outputs,
) -> int:
    """Multi-process batch parsing."""
    try:
        from concurrent.futures import ProcessPoolExecutor

        lines = [
            ln
            for ln in iter_lines(file)
            if ln.strip()
        ]

        workers = workers_requested(args)

        chunk_size = max(
            200,
            len(lines) // (workers * 4) + 1,
        )

        chunks = [
            lines[i:i + chunk_size]
            for i in range(
                0,
                len(lines),
                chunk_size,
            )
        ]

        cfg = load_pipeline_config(args.config)

        total = 0

        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_par_init,
            initargs=(cfg,),
        ) as pool:

            for events in pool.map(
                _par_chunk,
                chunks,
            ):
                for out in outputs:
                    out.write(events)

                total += len(events)

        pipeline.stats.inc(
            "received",
            total,
        )

        pipeline.stats.inc(
            "parsed",
            total,
        )

        return total

    except Exception as ex:
        print(
            "ULPF: parallel parsing unavailable "
            f"({ex}); using single process",
            file=sys.stderr,
        )
        return 0


_PAR_PIPELINE = None


def _par_init(cfg: dict) -> None:
    global _PAR_PIPELINE
    _PAR_PIPELINE = _build_pipeline(cfg)


def _par_chunk(
    lines: list[str],
) -> list[dict]:

    return [
        dict(
            _PAR_PIPELINE.process_raw(
                raw,
                {
                    "source_type": "file",
                    "address": "batch",
                },
            )
        )
        for raw in lines
    ]


def _print_event(
    event: dict,
    idx: int,
    c: Ansi,
    args,
) -> None:

    ues = event["ues"]
    meta = event["meta"]

    sev = ues.get(
        "severity_label",
        "info",
    )

    sev_color = {
        "critical": c.RED,
        "high": c.RED,
        "medium": c.YELLOW,
        "low": c.BLUE,
        "info": c.CYAN,
        "debug": c.GRAY,
    }.get(sev, "")

    print(
        f"{c.GRAY}[#{idx}]{c.RESET} "
        f"{c.BOLD}{meta.get('parser')}{c.RESET} "
        f"{c.GRAY}({meta.get('format')}){c.RESET} "
        f"{ues.get('event_time')} "
        f"{sev_color}{sev}"
        f"({ues.get('severity')}){c.RESET}"
    )

    fields = [
        f"category={ues.get('category')}",
        f"type={ues.get('type')}",
        f"action={ues.get('action')}",
        f"outcome={ues.get('outcome')}",
    ]

    print(
        f"      {c.GRAY}"
        f"{' '.join(fields)}"
        f"{c.RESET}"
    )

    src = ues.get("source") or {}
    dst = ues.get("destination") or {}
    net = ues.get("network") or {}

    conns = []

    if src.get("ip"):
        conns.append(
            f"src={src.get('ip')}:{src.get('port')}"
        )

    if dst.get("ip"):
        conns.append(
            f"dst={dst.get('ip')}:{dst.get('port')}"
        )

    if net.get("transport"):
        conns.append(
            f"transport={net.get('transport')}"
        )

    if (ues.get("user") or {}).get("name"):
        conns.append(
            f"user={ues['user']['name']}"
        )

    if conns:
        print(
            f"      {c.CYAN}"
            f"{'  '.join(conns)}"
            f"{c.RESET}"
        )

    if ues.get("message"):
        print(
            f"      msg: "
            f"{str(ues.get('message'))[:160]}"
        )

    threat = ues.get("threat") or {}

    for match in threat.get("matched") or []:
        print(
            f"      {c.RED}THREAT:{c.RESET} "
            f"{match.get('indicator')} "
            f"[{match.get('type')}/"
            f"{match.get('severity')}] "
            f"via {match.get('feed')}"
        )

    if getattr(args, "show_json", False):
        print(
            c.GRAY
            + json_dumps(
                event,
                pretty=True,
            )
            + c.RESET
        )


# ------------------------------------------------------------------------ inspect
def _guess_type(value) -> str:
    s = str(value)

    if re.fullmatch(r"[\d.]+", s):
        try:
            import ipaddress

            ipaddress.ip_address(s)
            return "ip"

        except ValueError:
            pass

    if re.fullmatch(r"\d+", s):
        return "int"

    try:
        float(s)
        return "float"

    except ValueError:
        pass

    if parse_timestamp(s):
        return "timestamp"

    return "str"


def cmd_inspect(args) -> int:
    c = _c(args)

    cfg = load_pipeline_config(args.config)
    specs = load_parser_specs(cfg)
    registry = ParserRegistry(specs)

    formats: Counter = Counter()
    parsers: Counter = Counter()
    keys: Counter = Counter()

    sample_attrs: dict = {}

    times_ok = 0
    n = 0

    for file in args.files:
        for raw in iter_lines(file):

            n += 1

            if args.lines and n > args.lines:
                break

            det = detect_format(raw)

            formats[det["format"]] += 1

            (
                result,
                parser,
                spec,
                det,
                chained,
            ) = registry.parse_chain(raw)

            pname = (
                spec.id
                if spec
                else parser.id
            )

            parsers[pname] += 1

            for key in result.attributes:
                keys[key] += 1

            if not sample_attrs:
                sample_attrs = dict(
                    result.attributes
                )

            if (
                result.event_time
                and parse_timestamp(
                    result.event_time
                )
            ):
                times_ok += 1

    print(
        f"{c.BOLD}"
        f"ULPF inspect: {n} records"
        f"{c.RESET}"
    )

    print(
        f"  detected formats : "
        f"{dict(formats.most_common())}"
    )

    print(
        f"  selected parsers : "
        f"{dict(parsers.most_common())}"
    )

    if n:
        print(
            f"  timestamps parsed: "
            f"{times_ok}/{n}"
        )

    print(
        f"  extracted fields : "
        f"{len(keys)} distinct"
    )

    print(
        f"{c.BOLD}"
        f"  top fields "
        f"(key -> suggested UES target: "
        f"{{src, type}})"
        f"{c.RESET}"
    )

    for key, count in keys.most_common(25):

        hit = INFERENCE_BY_KEY.get(
            str(key).lower()
        )

        target = (
            hit[0]
            if hit
            else "<target.path>"
        )

        ctype = _guess_type(
            sample_attrs.get(key, "")
        )

        print(
            f"    {key} ({count})"
        )

        print(
            f"      {target}: "
            f"{{src: {key}, type: {ctype}}}"
        )

    if args.suggest:

        print(
            f"{c.BOLD}"
            "starter parser config "
            "(edit targets, then save "
            "under configs/parsers/):"
            f"{c.RESET}"
        )

        print(
            _starter_yaml(
                args.files[0],
                registry,
                sample_attrs,
            )
        )

    return 0


# --------------------------------------------------------------- starter yaml
def _starter_yaml(
    file: str,
    registry: ParserRegistry,
    sample_attrs: dict,
) -> str:

    raw = next(
        iter(iter_lines(file)),
        "",
    )

    det = detect_format(raw)

    fmt = (
        det["format"]
        if (
            det["format"] in BUILTIN_CLASSES
            and det["format"] != "text"
        )
        else "regex"
    )

    mapping_lines = []

    for key in list(sample_attrs)[:20]:

        hit = INFERENCE_BY_KEY.get(
            str(key).lower()
        )

        ctype = _guess_type(
            sample_attrs.get(key, "")
        )

        target = (
            hit[0]
            if hit
            else None
        )

        if target in (
            "message",
            "event_time",
        ):
            continue

        if target:

            mapping_lines.append(
                f"  {target}: "
                f"{{src: {key}, type: {ctype}}}"
            )

        else:

            mapping_lines.append(
                f"  # unknown.target: "
                f"{{src: {key}, type: {ctype}}}"
            )

    base_id = (
        os.path.basename(file)
        .split(".")[0]
        .lower()
        .replace("-", "_")
    )

    lines = [
        f"id: {base_id}-custom",
        f"name: {base_id} source",
        "vendor: <VENDOR>",
        "product: <PRODUCT>",
        "priority: 50",
        "match:",
        "  any:",
        (
            "    - contains: "
            f"'{(sample_attrs or {}).get('logid', 'UNIQUE_MARKER')}'"
        ),
        f"format: {fmt}",
        "format_options: {}",
        "mapping:",
        *mapping_lines,
        "constants:",
        "  category: <network|authentication|web|system>",
    ]

    return "\n".join(lines)


# ------------------------------------------------------------------------ onboard
def cmd_onboard(args) -> int:
    """
    AI-assisted offline parser onboarding.

    Pipeline:

        unknown/vendor log
                ↓
        local deterministic AI
                ↓
        semantic UES mapping
                ↓
        confidence scoring
                ↓
        reviewable parser YAML

    No cloud API is used.
    """

    c = _c(args)

    # ------------------------------------------------------------
    # Load pipeline/parser registry
    # ------------------------------------------------------------
    try:
        cfg = load_pipeline_config(args.config)
        specs = load_parser_specs(cfg)
        registry = ParserRegistry(specs)

    except Exception as ex:
        print(
            f"{c.RED}CONFIG ERROR: {ex}{c.RESET}"
        )
        return 2

    sample_attrs: dict = {}

    sample_raw = ""
    n = 0

    chosen = Counter()

    # ------------------------------------------------------------
    # Read representative sample lines
    # ------------------------------------------------------------
    try:

        for raw in iter_lines(args.file):

            if not raw.strip():
                continue

            n += 1

            if not sample_raw:
                sample_raw = raw.strip()

            (
                result,
                parser,
                spec,
                det,
                chained,
            ) = registry.parse_chain(raw)

            parser_id = (
                spec.id
                if spec
                else parser.id
            )

            chosen[parser_id] += 1

            if not sample_attrs:
                sample_attrs = dict(
                    result.attributes
                )

            if n >= 20:
                break

    except Exception as ex:
        print(
            f"{c.RED}"
            f"ERROR reading sample: {ex}"
            f"{c.RESET}"
        )
        return 2

    if not sample_raw:

        print(
            f"{c.RED}"
            f"ERROR: no usable log lines found "
            f"in {args.file}"
            f"{c.RESET}"
        )

        return 2

    # ------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------
    detection = detect_format(
        sample_raw
    )

    detected_format = detection.get(
        "format",
        "text",
    )

    print()
    print(
        f"{c.BOLD}"
        "ULPF AI-Assisted Onboarding"
        f"{c.RESET}"
    )

    print("─" * 68)

    print(
        f"  source            : "
        f"{args.file}"
    )

    print(
        f"  sampled lines     : "
        f"{n}"
    )

    print(
        f"  detected format   : "
        f"{detected_format}"
    )

    print(
        f"  existing parser   : "
        f"{dict(chosen.most_common(3))}"
    )

    # ------------------------------------------------------------
    # Local AI analysis
    # ------------------------------------------------------------
    try:

        ai_result = local_ai_analyze(
            sample_raw
        )

    except Exception as ex:

        print(
            f"{c.RED}"
            f"AI analysis failed: {ex}"
            f"{c.RESET}"
        )

        return 2

    engine = ai_result.get(
        "engine",
        "offline",
    )

    mode = ai_result.get(
        "mode",
        "offline-assisted",
    )

    print(
        f"  mapping engine    : "
        f"{engine}"
    )

    print(
        f"  mode              : "
        f"{mode}"
    )

    print(
        f"  network required  : "
        f"{ai_result.get('network_access_required', False)}"
    )

    # ------------------------------------------------------------
    # Convert AI result to parser mappings
    # ------------------------------------------------------------
    suggestions = (
        ai_result.get("suggestions")
        or []
    )

    mappings = []
    mapped_sources = set()

    # These are the canonical parser targets
    # used by the ULPF UES structure.
    target_map = {
        "source.ip": "source.ip",
        "destination.ip": "destination.ip",
        "source.port": "source.port",
        "destination.port": "destination.port",
        "network.transport": "network.transport",
        "event.action": "action",
        "action": "action",
        "event.outcome": "outcome",
        "outcome": "outcome",
        "user.name": "user.name",
        "device.host": "device.host",
        "host.name": "device.host",
        "message": "message",
        "destination.service": "destination.service",
        "service.name": "destination.service",
        "geo.source.country": "geo.source.country",
        "geo.destination.country": "geo.destination.country",
    }

    for item in suggestions:

        if not isinstance(item, dict):
            continue

        source = str(
            item.get("source", "")
        ).strip()

        target = str(
            item.get("target", "")
        ).strip()

        if not source or not target:
            continue

        try:
            confidence = float(
                item.get(
                    "confidence",
                    0.0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            confidence = 0.0

        reason = str(
            item.get(
                "reason",
                "local inference",
            )
        )

        target = target_map.get(
            target,
            target,
        )

        sample_value = item.get(
            "sample",
            sample_attrs.get(
                source,
                "",
            ),
        )

        ctype = _guess_type(
            sample_value
        )

        mappings.append(
            {
                "source": source,
                "target": target,
                "type": ctype,
                "confidence": confidence,
                "reason": reason,
            }
        )

        mapped_sources.add(source)

    # ------------------------------------------------------------
    # Unknown fields
    # ------------------------------------------------------------
    unknown_fields = []

    ai_unknown = (
        ai_result.get(
            "unknown_fields"
        )
        or []
    )

    for field in ai_unknown:

        field = str(field).strip()

        if (
            field
            and field not in mapped_sources
        ):
            unknown_fields.append(
                field
            )

    # ------------------------------------------------------------
    # Print mapping result
    # ------------------------------------------------------------
    print()
    print(
        f"{c.BOLD}"
        "Semantic field mapping"
        f"{c.RESET}"
    )

    if mappings:

        for mapping in mappings:

            confidence = mapping[
                "confidence"
            ]

            if confidence >= 0.90:

                confidence_color = c.GREEN
                status = "HIGH"

            elif confidence >= 0.75:

                confidence_color = c.YELLOW
                status = "REVIEW"

            else:

                confidence_color = c.RED
                status = "LOW"

            print(
                f"    "
                f"{mapping['source']:<14}"
                f" → "
                f"{mapping['target']:<24}"
                f" "
                f"{confidence_color}"
                f"{confidence:.2f}"
                f" {status}"
                f"{c.RESET}"
            )

            print(
                f"                     "
                f"reason: "
                f"{mapping['reason']}"
            )

    else:

        print(
            f"    {c.YELLOW}"
            "No semantic mappings inferred."
            f"{c.RESET}"
        )

    if unknown_fields:

        print()
        print(
            f"{c.YELLOW}"
            "Fields requiring human review:"
            f"{c.RESET}"
        )

        for field in unknown_fields:
            print(
                f"    - {field}"
            )

    else:

        print()

        print(
            f"{c.GREEN}"
            "Unmapped fields: none"
            f"{c.RESET}"
        )

    # ------------------------------------------------------------
    # Determine parser format
    # ------------------------------------------------------------
    fmt = detected_format

    if (
        fmt not in BUILTIN_CLASSES
        or fmt == "text"
    ):
        fmt = "regex"

    # ------------------------------------------------------------
    # Detect vendor/product for CEF
    # ------------------------------------------------------------
    vendor = "<VENDOR>"
    product = "<PRODUCT>"

    if fmt == "cef":

        vendor_match = re.search(
            r"^CEF:\d+\|([^|]+)\|([^|]+)\|",
            sample_raw,
        )

        if vendor_match:

            vendor = vendor_match.group(1)
            product = vendor_match.group(2)

    # ------------------------------------------------------------
    # Generate parser match marker
    # ------------------------------------------------------------
    marker = ""

    if fmt == "cef":

        marker_match = re.search(
            r"^CEF:\d+\|[^|]+\|[^|]+\|",
            sample_raw,
        )

        if marker_match:
            marker = (
                marker_match
                .group(0)
                .rstrip("|")
            )

    if not marker:

        kv_match = re.search(
            r"(?<![\w.-])"
            r"([A-Za-z_][\w.-]*)"
            r"\s*=",
            sample_raw,
        )

        if kv_match:

            marker = (
                kv_match.group(1)
                + "="
            )

    if not marker:
        marker = "UNIQUE_MARKER"

    # ------------------------------------------------------------
    # Build YAML mapping
    # ------------------------------------------------------------
    mapping_lines = []

    used_targets = set()

    for mapping in mappings:

        source = mapping["source"]
        target = mapping["target"]
        ctype = mapping["type"]

        # Avoid duplicate target definitions.
        if target in used_targets:
            continue

        # Timestamp is handled by pipeline timestamp extraction.
        if target == "event_time":
            continue

        used_targets.add(target)

        mapping_lines.append(
            f"  {target}: "
            f"{{src: {source}, type: {ctype}}}"
        )

    if not mapping_lines:

        mapping_lines.append(
            "  # No confident mappings generated"
        )

    # ------------------------------------------------------------
    # Category inference
    # ------------------------------------------------------------
    category = "network"

    target_text = " ".join(
        m["target"].lower()
        for m in mappings
    )

    if any(
        value in target_text
        for value in (
            "user.name",
            "authentication",
        )
    ):
        category = "authentication"

    elif any(
        value in target_text
        for value in (
            "http",
            "web",
            "url",
        )
    ):
        category = "web"

    elif any(
        value in target_text
        for value in (
            "process",
            "host",
            "system",
        )
    ):
        category = "system"

    # ------------------------------------------------------------
    # Generate YAML
    # ------------------------------------------------------------
    yaml_lines = [
        f"id: {args.id}",
        f"name: {args.id} AI-assisted source",
        f"vendor: {vendor}",
        f"product: {product}",
        "priority: 80",
        "match:",
        "  any:",
        f"    - contains: '{marker}'",
        f"format: {fmt}",
        "format_options: {}",
        "mapping:",
        *mapping_lines,
        "constants:",
        f"  category: {category}",
    ]

    yaml_text = "\n".join(
        yaml_lines
    )

    # ------------------------------------------------------------
    # Write parser configuration
    # ------------------------------------------------------------
    out_path = (
        args.out
        or os.path.join(
            "configs",
            "parsers",
            f"{args.id}.yaml",
        )
    )

    try:

        os.makedirs(
            os.path.dirname(
                out_path
            ) or ".",
            exist_ok=True,
        )

        with open(
            out_path,
            "w",
            encoding="utf-8",
        ) as fh:

            fh.write(
                yaml_text
                + "\n"
            )

    except Exception as ex:

        print(
            f"{c.RED}"
            f"ERROR writing parser: {ex}"
            f"{c.RESET}"
        )

        return 2

    # ------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------
    print()
    print(
        f"{c.GREEN}"
        "Generated parser configuration"
        f"{c.RESET}"
    )

    print(
        f"  file                : "
        f"{out_path}"
    )

    print(
        f"  parser id           : "
        f"{args.id}"
    )

    print(
        f"  format              : "
        f"{fmt}"
    )

    print(
        f"  mappings generated  : "
        f"{len(used_targets)}"
    )

    print(
        f"  category            : "
        f"{category}"
    )

    if ai_result.get(
        "local_model_error"
    ):

        print(
            f"  {c.YELLOW}"
            "local model fallback : "
            f"{ai_result['local_model_error']}"
            f"{c.RESET}"
        )

    print()

    print(
        f"{c.BOLD}"
        "Next steps:"
        f"{c.RESET}"
    )

    print(
        f"  1. Review:"
        f" {out_path}"
    )

    print(
        f"  2. Validate:"
    )

    print(
        f"     ulpf validate "
        f"--file {args.file}"
    )

    print()

    print(
        f"{c.GREEN}"
        "Status: parser generated "
        "and ready for review."
        f"{c.RESET}"
    )

    return 0


# ----------------------------------------------------------------------- validate
def cmd_validate(args) -> int:
    c = _c(args)

    try:
        cfg = load_pipeline_config(
            args.config
        )

        specs = load_parser_specs(
            cfg
        )

    except Exception as ex:

        print(
            f"{c.RED}"
            f"CONFIG ERROR: {ex}"
            f"{c.RESET}"
        )

        return 2

    print(
        f"{c.GREEN}"
        "config OK"
        f"{c.RESET}: "
        f"pipeline_id="
        f"{cfg.get('pipeline_id')} "
        f"inputs="
        f"{len(cfg.get('inputs') or [])} "
        f"outputs="
        f"{len(cfg.get('outputs') or [])} "
        f"parser_configs="
        f"{len(specs)}"
    )

    for spec in specs:

        print(
            f"  parser: "
            f"{spec.get('id')} "
            f"({spec.get('format')}) "
            f"vendor="
            f"{spec.get('vendor')}"
        )

    if args.file:

        pipeline = _build_pipeline(
            cfg
        )

        parsed = 0
        failed = 0

        for i, raw in enumerate(
            iter_lines(args.file)
        ):

            if i >= 200:
                break

            event = pipeline.process_raw(
                raw,
                {
                    "source_type": "file",
                    "address": args.file,
                },
            )

            if (
                event["meta"]["parse_status"]
                == "parsed"
            ):
                parsed += 1
            else:
                failed += 1

        print(
            f"  sample parse: "
            f"{parsed} parsed, "
            f"{failed} failed "
            f"(first 200 lines)"
        )

        if failed:
            return 1

    print(
        f"{c.GREEN}"
        "ULPF validation PASSED"
        f"{c.RESET}"
    )

    return 0


# ------------------------------------------------------------------------- schema
def cmd_schema(args) -> int:

    payload = {
        "ues_version": UES_VERSION,
        "schema": UES_SCHEMA,
    }

    if args.format == "text":

        def _walk(
            node,
            prefix="",
        ):

            for key, value in node.items():

                if isinstance(
                    value,
                    dict,
                ):

                    print(
                        f"  {prefix}{key}:"
                    )

                    _walk(
                        value,
                        prefix + "  ",
                    )

                else:

                    print(
                        f"  {prefix}{key}"
                    )

        _walk(
            UES_SCHEMA
        )

    else:

        print(
            json_dumps(
                payload,
                pretty=True,
            )
        )

    return 0


# --------------------------------------------------------------------------- send
def cmd_send(args) -> int:

    proto = (
        socket.SOCK_DGRAM
        if args.proto == "udp"
        else socket.SOCK_STREAM
    )

    family = (
        socket.AF_INET6
        if ":" in args.host
        else socket.AF_INET
    )

    sock = socket.socket(
        family,
        proto,
    )

    sock.settimeout(5)

    if args.proto == "tcp":
        sock.connect(
            (
                args.host,
                args.port,
            )
        )

    sent = 0

    delay = (
        1.0 / max(args.rate, 1)
    )

    started = time.time()

    for _ in range(
        max(args.repeat, 1)
    ):

        stream = (
            iter_lines(args.file)
            if args.file != "-"
            else sys.stdin
        )

        for raw in stream:

            data = raw.encode(
                "utf-8",
                errors="replace",
            )

            if args.proto == "udp":

                sock.sendto(
                    data,
                    (
                        args.host,
                        args.port,
                    ),
                )

            else:

                sock.sendall(
                    data + b"\n"
                )

            sent += 1

            if args.rate > 0:
                time.sleep(delay)

    sock.close()

    print(
        f"sent {sent} events to "
        f"{args.host}:{args.port}/"
        f"{args.proto} "
        f"in "
        f"{time.time() - started:.2f}s"
    )

    return 0


# -------------------------------------------------------------------------- query
def cmd_query(args) -> int:

    import sqlite3

    conn = sqlite3.connect(
        args.db
    )

    conn.row_factory = sqlite3.Row

    sql = (
        args.sql
        or
        "SELECT event_time, category, "
        "action, outcome, severity_label, "
        "source_ip, source_port, "
        "destination_ip, destination_port, "
        "user, message FROM events "
        "ORDER BY event_time DESC "
        "LIMIT ?"
    )

    if "?" not in (
        args.sql or ""
    ):

        rows = conn.execute(
            sql,
            (args.limit,),
        ).fetchall()

    else:

        rows = conn.execute(
            args.sql
        ).fetchall()

    for row in rows:

        print(
            json.dumps(
                dict(row),
                ensure_ascii=False,
                default=str,
            )
        )

    if not rows:
        print("-- no rows")

    conn.close()

    return 0


# --------------------------------------------------------------------- benchmark
def cmd_benchmark(args) -> int:

    import glob as _glob

    cfg = load_pipeline_config(
        args.config
    )

    pipeline = _build_pipeline(
        cfg
    )

    files = (
        args.files
        or sorted(
            _glob.glob(
                "samples/*.log"
            )
        )
    )

    lines = []

    for f in files:

        lines.extend(
            iter_lines(f)
        )

    if not lines:

        print(
            "no input lines found "
            "(pass files or run from repo root)"
        )

        return 1

    rounds = args.rounds

    started = time.time()

    count = 0

    for _ in range(rounds):

        for raw in lines:

            pipeline.process_raw(
                raw,
                {
                    "source_type": "file",
                    "address": "benchmark",
                },
            )

            count += 1

    elapsed = (
        time.time() - started
    )

    print(
        f"benchmark: {count} events "
        f"in {elapsed:.2f}s "
        f"-> {count / elapsed:,.0f} "
        f"events/sec "
        f"(single process, "
        f"{len(lines)} unique lines "
        f"x {rounds} rounds)"
    )

    return 0


# ------------------------------------------------------------------------- doctor
def cmd_doctor(args) -> int:

    c = _c(args)

    problems = []

    if sys.version_info < (
        3,
        9,
    ):

        problems.append(
            "python >= 3.9 required, "
            f"found {sys.version_info}"
        )

    if not args.quiet:

        print(
            f"{c.BOLD}"
            "ULPF doctor"
            f"{c.RESET} "
            f"v{__version__}"
        )

        print(
            f"  python        : "
            f"{sys.version_info.major}."
            f"{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        )

        try:

            import yaml  # noqa: F401

            print(
                "  PyYAML        : "
                "installed "
                "(full YAML support)"
            )

        except ImportError:

            print(
                "  PyYAML        : "
                "not installed "
                "(using built-in "
                "mini-YAML loader)"
            )

        try:

            import kafka  # noqa: F401

            print(
                "  kafka-python  : "
                "installed "
                "(Kafka sink available)"
            )

        except ImportError:

            print(
                "  kafka-python  : "
                "not installed "
                "(optional; file sinks "
                "work without it)"
            )

    try:

        cfg = load_pipeline_config(
            args.config
        )

        specs = load_parser_specs(
            cfg
        )

        if not args.quiet:

            print(
                f"  config        : "
                f"OK "
                f"({cfg.get('pipeline_id')}, "
                f"{len(specs)} parser configs)"
            )

    except Exception as ex:

        problems.append(
            f"config: {ex}"
        )

    if not args.quiet:

        print(
            "  raw preservation : "
            "enabled by design "
            "(raw + sha256 in every event)"
        )

    if problems:

        if not args.quiet:

            for problem in problems:

                print(
                    f"{c.RED}"
                    f"  PROBLEM: {problem}"
                    f"{c.RESET}"
                )

        return 1

    if not args.quiet:

        print(
            f"{c.GREEN}"
            "  environment healthy"
            f"{c.RESET}"
        )

    return 0


# --------------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:

    ap = argparse.ArgumentParser(
        prog="ulpf",
        description=(
            "Universal Log Pre-processing "
            "Framework - ingest, parse, "
            "normalize any log into a "
            "lossless analytics-ready "
            "universal event schema."
        ),
    )

    ap.add_argument(
        "--version",
        action="version",
        version=f"ulpf {__version__}",
    )

    sub = ap.add_subparsers(
        dest="command",
        required=True,
    )

    # --------------------------------------------------------------- run
    p = sub.add_parser(
        "run",
        help=(
            "run the pipeline daemon "
            "(inputs -> outputs)"
        ),
    )

    p.add_argument(
        "--config",
        help=(
            "pipeline config path "
            "(default: auto-discover)"
        ),
    )

    p.set_defaults(
        func=cmd_run
    )

    # --------------------------------------------------------------- parse
    p = sub.add_parser(
        "parse",
        help=(
            "one-shot parse of files "
            "(or stdin with '-')"
        ),
    )

    p.add_argument(
        "files",
        nargs="*",
        help=(
            "log files to parse; "
            "'-' reads stdin"
        ),
    )

    p.add_argument(
        "--config"
    )

    p.add_argument(
        "--output",
        action="append",
        help=(
            "sink: 'stdout' or "
            "type:path, e.g. "
            "jsonl:out.jsonl, "
            "sqlite:out.db "
            "(repeatable)"
        ),
    )

    p.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON output",
    )

    p.add_argument(
        "--show-json",
        action="store_true",
        help=(
            "also print full JSON "
            "in pretty mode"
        ),
    )

    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "max events to display "
            "(0 = all)"
        ),
    )

    p.add_argument(
        "--workers",
        type=int,
        default=1,
        help=(
            "parallel worker processes "
            "for large files"
        ),
    )

    p.add_argument(
        "--no-color",
        action="store_true",
    )

    p.set_defaults(
        func=cmd_parse
    )

    # -------------------------------------------------------------- inspect
    p = sub.add_parser(
        "inspect",
        help=(
            "analyze a log file: formats, "
            "parsers, field inventory"
        ),
    )

    p.add_argument(
        "files",
        nargs="+",
    )

    p.add_argument(
        "--config"
    )

    p.add_argument(
        "--lines",
        type=int,
        default=200,
        help=(
            "max lines per file "
            "to inspect"
        ),
    )

    p.add_argument(
        "--suggest",
        action="store_true",
        help=(
            "print a starter parser config"
        ),
    )

    p.add_argument(
        "--no-color",
        action="store_true",
    )

    p.set_defaults(
        func=cmd_inspect
    )

    # --------------------------------------------------------------- onboard
    p = sub.add_parser(
        "onboard",
        help=(
            "AI-assisted offline "
            "plug-and-play parser "
            "onboarding"
        ),
    )

    p.add_argument(
        "file",
        help="sample/vendor log file",
    )

    p.add_argument(
        "--id",
        required=True,
        help=(
            "parser id, e.g. "
            "myvendor-fw"
        ),
    )

    p.add_argument(
        "--out",
        help=(
            "output YAML path "
            "(default: "
            "configs/parsers/<id>.yaml)"
        ),
    )

    p.add_argument(
        "--config",
        help="pipeline config path",
    )

    p.add_argument(
        "--no-color",
        action="store_true",
    )

    p.set_defaults(
        func=cmd_onboard
    )

    # -------------------------------------------------------------- validate
    p = sub.add_parser(
        "validate",
        help=(
            "validate config and "
            "parser plugins"
        ),
    )

    p.add_argument(
        "--config"
    )

    p.add_argument(
        "--file",
        help=(
            "optionally sample-parse "
            "this file"
        ),
    )

    p.add_argument(
        "--no-color",
        action="store_true",
    )

    p.set_defaults(
        func=cmd_validate
    )

    # ---------------------------------------------------------------- schema
    p = sub.add_parser(
        "schema",
        help=(
            "print the Universal "
            "Event Schema"
        ),
    )

    p.add_argument(
        "--format",
        choices=[
            "json",
            "text",
        ],
        default="json",
    )

    p.set_defaults(
        func=cmd_schema
    )

    # ------------------------------------------------------------------- send
    p = sub.add_parser(
        "send",
        help=(
            "replay a log file to "
            "a syslog receiver "
            "(for demos/tests)"
        ),
    )

    p.add_argument(
        "file"
    )

    p.add_argument(
        "--host",
        default="127.0.0.1",
    )

    p.add_argument(
        "--port",
        type=int,
        default=5514,
    )

    p.add_argument(
        "--proto",
        choices=[
            "udp",
            "tcp",
        ],
        default="udp",
    )

    p.add_argument(
        "--rate",
        type=float,
        default=100,
        help=(
            "events per second "
            "(0 = unlimited)"
        ),
    )

    p.add_argument(
        "--repeat",
        type=int,
        default=1,
    )

    p.set_defaults(
        func=cmd_send
    )

    # ------------------------------------------------------------------ query
    p = sub.add_parser(
        "query",
        help=(
            "query a SQLite "
            "output database"
        ),
    )

    p.add_argument(
        "db"
    )

    p.add_argument(
        "--sql",
        help=(
            "custom SQL "
            "(use ? for the "
            "default LIMIT param)"
        ),
    )

    p.add_argument(
        "--limit",
        type=int,
        default=20,
    )

    p.set_defaults(
        func=cmd_query
    )

    # --------------------------------------------------------------- benchmark
    p = sub.add_parser(
        "benchmark",
        help=(
            "measure parsing "
            "throughput"
        ),
    )

    p.add_argument(
        "--files",
        nargs="*",
    )

    p.add_argument(
        "--config"
    )

    p.add_argument(
        "--rounds",
        type=int,
        default=5,
    )

    p.set_defaults(
        func=cmd_benchmark
    )

    # ----------------------------------------------------------------- doctor
    p = sub.add_parser(
        "doctor",
        help=(
            "check the runtime "
            "environment"
        ),
    )

    p.add_argument(
        "--config"
    )

    p.add_argument(
        "--quiet",
        action="store_true",
        help="exit code only",
    )

    p.add_argument(
        "--no-color",
        action="store_true",
    )

    p.set_defaults(
        func=cmd_doctor
    )

    return ap


def main(argv=None) -> int:

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    return int(
        args.func(args) or 0
    )


if __name__ == "__main__":
    sys.exit(main())