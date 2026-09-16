"""Configuration loading and validation (mini-YAML with PyYAML if available)."""
from __future__ import annotations

import glob
import os
from pathlib import Path

from ulpf.miniyaml import loads as mini_loads

try:  # optional - not required for air-gapped installs
    import yaml as _pyyaml
except ImportError:  # pragma: no cover
    _pyyaml = None


def load_yaml_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if _pyyaml is not None:
        try:
            data = _pyyaml.safe_load(text)
            return data or {}
        except Exception:
            pass
    return mini_loads(text)


def loads_any(text: str) -> dict:
    if _pyyaml is not None:
        try:
            return _pyyaml.safe_load(text) or {}
        except Exception:
            pass
    return mini_loads(text)


DEFAULT_CONFIG = {
    "pipeline_id": "ulpf-core",
    "pipeline_version": "1.0.0",
    "parser_config_dirs": ["configs/parsers"],
    "pipeline": {
        "workers": 4,
        "queue_size": 50000,
        "batch_size": 1000,
        "flush_interval": 1.0,
        "stats_interval": 10.0,
    },
    "enrichment": {
        "enrichers": ["time", "ip", "geo", "threat_intel", "classify", "severity", "integrity"],
        "geo_ranges_csv": "configs/enrichment/geo_ranges.csv",
        "threat_intel_csv": "configs/enrichment/threat_intel.csv",
    },
    "inputs": [
        {"type": "syslog", "host": "0.0.0.0", "udp_port": 5514, "tcp_port": 5514},
    ],
    "outputs": [
        {"type": "stdout"},
        {"type": "jsonl", "path": "data/events.jsonl", "rotate_size_mb": 100},
        {"type": "raw_archive", "path": "data/raw"},
        {"type": "sqlite", "path": "data/events.db"},
    ],
}

_VALID_INPUT_TYPES = {"syslog", "file", "dir", "stdin"}
_VALID_OUTPUT_TYPES = {"stdout", "jsonl", "raw_archive", "sqlite", "http", "elasticsearch", "kafka", "null"}


def _expand(obj):
    if isinstance(obj, dict):
        return {k: _expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v) for v in obj]
    if isinstance(obj, str):
        from ulpf.utils import expand_env
        return expand_env(obj)
    return obj


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def find_config_file(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    for candidate in (os.environ.get("ULPF_CONFIG"), "ulpf.yaml",
                      "configs/pipeline.yaml", "/etc/ulpf/pipeline.yaml"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def load_pipeline_config(path: str | None = None) -> dict:
    cfg_path = find_config_file(path)
    cfg = dict(DEFAULT_CONFIG)
    if cfg_path:
        file_cfg = load_yaml_file(cfg_path)
        cfg = _deep_merge(cfg, file_cfg)
        cfg["_config_path"] = cfg_path
    cfg = _expand(cfg)
    validate_pipeline_config(cfg)
    return cfg


def validate_pipeline_config(cfg: dict) -> None:
    pipeline = cfg.get("pipeline") or {}
    if not isinstance(pipeline, dict):
        raise ValueError("pipeline: must be a mapping")
    for key in ("workers", "queue_size", "batch_size"):
        value = pipeline.get(key)
        if not isinstance(value, int) or value < 1:
            raise ValueError(f"pipeline.{key} must be a positive integer, got {value!r}")
    inputs = cfg.get("inputs") or []
    if not isinstance(inputs, list):
        raise ValueError("inputs: must be a list")
    for i, src in enumerate(inputs):
        if not isinstance(src, dict) or src.get("type") not in _VALID_INPUT_TYPES:
            raise ValueError(f"inputs[{i}]: unknown or missing type ({_VALID_INPUT_TYPES})")
    outputs = cfg.get("outputs") or []
    if not isinstance(outputs, list):
        raise ValueError("outputs: must be a list")
    for i, out in enumerate(outputs):
        if not isinstance(out, dict) or out.get("type") not in _VALID_OUTPUT_TYPES:
            raise ValueError(f"outputs[{i}]: unknown or missing type ({_VALID_OUTPUT_TYPES})")


def load_parser_specs(cfg: dict) -> list[dict]:
    """Load all YAML parser configs from the configured directories."""
    specs = []
    seen_ids = set()
    for pattern in cfg.get("parser_config_dirs") or []:
        for path in sorted(glob.glob(os.path.join(str(pattern), "*.yaml")) +
                           glob.glob(os.path.join(str(pattern), "*.yml"))):
            try:
                data = load_yaml_file(path)
            except Exception as ex:
                raise ValueError(f"parser config {path}: {ex}") from ex
            if not isinstance(data, dict) or not data.get("id"):
                raise ValueError(f"parser config {path}: must be a mapping with an 'id'")
            if data["id"] in seen_ids:
                raise ValueError(f"parser config {path}: duplicate id '{data['id']}'")
            seen_ids.add(data["id"])
            data["_path"] = path
            specs.append(data)
    return specs


def discover_plugins(root: str = "plugins") -> list[dict]:
    """Discover and validate offline plugin manifests.

    YAML parser specifications remain the active parser configuration; plugin
    packages are discovered separately so an invalid optional plugin cannot
    disable the core pipeline.
    """
    found = []
    base = Path(root)
    if not base.exists():
        return found
    for manifest in sorted(base.glob("*/manifest.y*ml")):
        plugin_dir = manifest.parent
        data = load_yaml_file(str(manifest))
        required = ("id", "name", "version", "entrypoint", "mapping_file")
        missing = [key for key in required if not data.get(key)]
        entrypoint = plugin_dir / str(data.get("entrypoint", ""))
        mapping = plugin_dir / str(data.get("mapping_file", ""))
        tests = plugin_dir / str(data.get("test_directory", "tests"))
        if missing or not entrypoint.is_file() or not mapping.is_file() or not tests.is_dir():
            data["status"] = "invalid"
            data["validation_errors"] = (
                [f"missing manifest field: {key}" for key in missing]
                + ([] if entrypoint.is_file() else ["entrypoint not found"])
                + ([] if mapping.is_file() else ["mapping_file not found"])
                + ([] if tests.is_dir() else ["test_directory not found"])
            )
        else:
            data["status"] = "valid"
            data["validation_errors"] = []
        data["_path"] = str(plugin_dir)
        found.append(data)
    return found
