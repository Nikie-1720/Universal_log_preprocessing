from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


class PluginLifecycleError(Exception):
    pass


class PluginNotFoundError(PluginLifecycleError):
    pass


class InvalidTransitionError(PluginLifecycleError):
    pass


class PluginLifecycle:
    """Local, air-gapped lifecycle for AI-assisted parser plugins."""

    VALID_STATES = {"ANALYZED", "DRAFT", "VALIDATED", "APPROVED", "ACTIVE", "REJECTED"}

    def __init__(self, root, *, plugin_root=None, parser_root=None, state_file=None):
        self.root = Path(root).resolve()
        self.plugin_root = Path(plugin_root or self.root / "plugins").resolve()
        self.parser_root = Path(parser_root or self.root / "configs" / "parsers").resolve()
        self.state_file = Path(state_file or self.root / "data" / "plugin-lifecycle" / "state.json").resolve()
        self._ensure_dirs()
        self._state = self._load_state()

    @staticmethod
    def _utc_now():
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _safe_id(plugin_id):
        plugin_id = str(plugin_id).strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,48}", plugin_id):
            raise ValueError("Invalid plugin_id")
        return plugin_id

    def _ensure_dirs(self):
        self.plugin_root.mkdir(parents=True, exist_ok=True)
        self.parser_root.mkdir(parents=True, exist_ok=True)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_state(self):
        if not self.state_file.exists():
            return {"version": 1, "updated_at": self._utc_now(), "plugins": {}}
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return {"version": 1, "updated_at": self._utc_now(), "plugins": {}}
        data.setdefault("version", 1)
        data.setdefault("plugins", {})
        return data

    def _save_state(self):
        self._state["updated_at"] = self._utc_now()
        fd, tmp = tempfile.mkstemp(prefix=".plugin-state-", suffix=".tmp", dir=str(self.state_file.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.state_file)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _plugin_dir(self, plugin_id):
        p = (self.plugin_root / self._safe_id(plugin_id)).resolve()
        p.relative_to(self.plugin_root)
        return p

    def _parser_path(self, plugin_id):
        p = (self.parser_root / f"{self._safe_id(plugin_id)}.yaml").resolve()
        p.relative_to(self.parser_root)
        return p

    @staticmethod
    def _sha256(text):
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _record(self, plugin_id, state, event, actor="system", details=None):
        plugin_id = self._safe_id(plugin_id)
        plugin = self._state["plugins"].setdefault(plugin_id, {
            "plugin_id": plugin_id,
            "created_at": self._utc_now(),
            "history": [],
        })
        previous = plugin.get("state")
        plugin["state"] = state
        plugin["updated_at"] = self._utc_now()
        plugin.setdefault("history", []).append({
            "timestamp": self._utc_now(),
            "event": event,
            "from_state": previous,
            "to_state": state,
            "actor": actor,
            "details": details or {},
        })
        plugin["history"] = plugin["history"][-200:]
        self._state["plugins"][plugin_id] = plugin
        self._save_state()
        return dict(plugin)

    def get_plugin(self, plugin_id):
        plugin_id = self._safe_id(plugin_id)
        p = self._state["plugins"].get(plugin_id)
        return dict(p) if p else None

    def require_plugin(self, plugin_id):
        p = self.get_plugin(plugin_id)
        if p is None:
            raise PluginNotFoundError(f"Plugin not found: {plugin_id}")
        return p

    def list_plugins(self):
        return sorted(self._state["plugins"].values(), key=lambda x: x.get("updated_at", ""), reverse=True)

    def create_draft(self, plugin_id, raw, analysis, parser_yaml):
        plugin_id = self._safe_id(plugin_id)
        if not str(raw).strip():
            raise ValueError("raw sample cannot be empty")
        if not isinstance(analysis, dict):
            raise ValueError("analysis must be an object")
        if not str(parser_yaml).strip():
            raise ValueError("parser_yaml cannot be empty")

        d = self._plugin_dir(plugin_id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "parser.yaml").write_text(parser_yaml, encoding="utf-8")
        (d / "sample.log").write_text(str(raw), encoding="utf-8")
        metadata = {
            "plugin_id": plugin_id,
            "created_at": self._utc_now(),
            "lifecycle": "DRAFT",
            "offline": True,
            "network_access_required": False,
            "analysis": analysis,
            "sample_sha256": self._sha256(str(raw)),
            "parser_sha256": self._sha256(parser_yaml),
        }
        (d / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return self._record(plugin_id, "DRAFT", "draft_created", "local-ai", metadata)

    def validate_plugin(self, plugin_id, *, registry, sample_raw=None):
        plugin_id = self._safe_id(plugin_id)
        plugin = self.require_plugin(plugin_id)
        if plugin.get("state") not in {"DRAFT", "REJECTED"}:
            if plugin.get("state") == "VALIDATED":
                return plugin
            raise InvalidTransitionError(f"Cannot validate from {plugin.get('state')}")

        parser_path = self._plugin_dir(plugin_id) / "parser.yaml"
        if not parser_path.exists():
            raise PluginLifecycleError("parser.yaml not found")
        parser_yaml = parser_path.read_text(encoding="utf-8")

        try:
            import yaml
            cfg = yaml.safe_load(parser_yaml)
        except Exception as exc:
            raise PluginLifecycleError(f"Invalid parser YAML: {exc}") from exc
        if not isinstance(cfg, dict):
            raise PluginLifecycleError("parser.yaml must be a YAML object")
        if str(cfg.get("id", "")).strip() != plugin_id:
            raise PluginLifecycleError("parser.yaml id does not match plugin_id")

        if sample_raw is None:
            sample_path = self._plugin_dir(plugin_id) / "sample.log"
            if not sample_path.exists():
                raise PluginLifecycleError("No validation sample available")
            sample_raw = sample_path.read_text(encoding="utf-8")

        # Use a temporary registry containing only the generated parser.
        from ulpf.registry import ParserRegistry
        test_registry = ParserRegistry([cfg])
        result = test_registry.validate_parser(plugin_id, sample_raw)
        if not result.get("ok"):
            raise PluginLifecycleError(result.get("error", "Parser validation failed"))

        result = dict(result)
        result["parser_sha256"] = self._sha256(parser_yaml)
        return self._record(plugin_id, "VALIDATED", "parser_validated", "validator", result)

    def approve_plugin(self, plugin_id, reviewer):
        plugin = self.require_plugin(plugin_id)
        if plugin.get("state") != "VALIDATED":
            raise InvalidTransitionError("Only VALIDATED plugins can be approved")
        reviewer = str(reviewer).strip()
        if not reviewer:
            raise ValueError("reviewer is required")
        parser_yaml = (self._plugin_dir(plugin_id) / "parser.yaml").read_text(encoding="utf-8")
        return self._record(plugin_id, "APPROVED", "human_approved", reviewer, {
            "reviewer": reviewer,
            "parser_sha256": self._sha256(parser_yaml),
        })

    def reject_plugin(self, plugin_id, reviewer, reason):
        plugin = self.require_plugin(plugin_id)
        if plugin.get("state") == "ACTIVE":
            raise InvalidTransitionError("ACTIVE plugins cannot be rejected here")
        reason = str(reason).strip()
        if not reason:
            raise ValueError("reason is required")
        return self._record(plugin_id, "REJECTED", "plugin_rejected", str(reviewer).strip() or "operator", {"reason": reason})

    def reopen_plugin(self, plugin_id, actor="operator"):
        plugin = self.require_plugin(plugin_id)
        if plugin.get("state") != "REJECTED":
            raise InvalidTransitionError("Only REJECTED plugins can be reopened")
        return self._record(plugin_id, "DRAFT", "plugin_reopened", actor)

    def activate_plugin(self, plugin_id, *, registry):
        plugin_id = self._safe_id(plugin_id)
        plugin = self.require_plugin(plugin_id)
        if plugin.get("state") != "APPROVED":
            raise InvalidTransitionError("Only APPROVED plugins can be activated")

        source = self._plugin_dir(plugin_id) / "parser.yaml"
        destination = self._parser_path(plugin_id)
        if not source.exists():
            raise PluginLifecycleError("Approved parser.yaml does not exist")
        parser_yaml = source.read_text(encoding="utf-8")
        current_hash = self._sha256(parser_yaml)

        approved_hash = None
        for h in reversed(plugin.get("history", [])):
            if h.get("to_state") == "APPROVED":
                approved_hash = h.get("details", {}).get("parser_sha256")
                break
        if approved_hash and approved_hash != current_hash:
            raise PluginLifecycleError("Approved parser changed after approval; re-validation required")

        fd, tmp = tempfile.mkstemp(prefix=f".{plugin_id}-", suffix=".yaml.tmp", dir=str(self.parser_root), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(parser_yaml)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, destination)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

        # Reload the live registry only after atomic parser installation.
        try:
            cfg = __import__("ulpf.config", fromlist=["load_pipeline_config", "load_parser_specs"])
            pipeline_cfg = cfg.load_pipeline_config(os.environ.get("ULPF_CONFIG"))
            specs = cfg.load_parser_specs(pipeline_cfg)
            registry.reload(specs)
        except Exception as exc:
            raise PluginLifecycleError(f"Parser installed but registry reload failed: {exc}") from exc

        result = self._record(plugin_id, "ACTIVE", "plugin_activated", "operator", {
            "parser_path": str(destination),
            "parser_sha256": current_hash,
        })
        result["parser_path"] = str(destination)
        return result
