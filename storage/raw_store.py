"""Immutable raw-event evidence storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RawStore:
    def __init__(self, root: str | None = None) -> None:
        self.root = Path(
            root or os.getenv("ULPF_RAW_STORE", "/data/raw")
        )
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe(value: Any) -> str:
        value = str(value or "unknown")
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:80]

    @staticmethod
    def _received_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

        return datetime.now(timezone.utc)

    def put(
        self,
        raw: Any,
        trace_id: str,
        source_type: str | None = None,
        received_time: Any = None,
    ) -> dict[str, Any]:

        raw_text = (
            raw
            if isinstance(raw, str)
            else json.dumps(
                raw,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )

        raw_bytes = raw_text.encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()

        received = self._received_datetime(received_time)

        source = self._safe(source_type)

        directory = (
            self.root
            / f"{received.year:04d}"
            / f"{received.month:02d}"
            / f"{received.day:02d}"
            / source
        )

        directory.mkdir(parents=True, exist_ok=True)

        safe_trace = self._safe(trace_id)

        final_path = directory / f"{safe_trace}.raw"

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{safe_trace}.",
            suffix=".tmp",
            dir=str(directory),
        )

        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw_bytes)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temp_name, final_path)

        finally:
            try:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            except OSError:
                pass

        return {
            "raw_event_id": f"raw-{safe_trace}",
            "raw_hash": digest,
            "sha256": digest,
            "raw_size": len(raw_bytes),
            "raw_path": str(final_path),
        }

    @staticmethod
    def verify(path: str | Path, expected_hash: str) -> dict[str, Any]:
        """Verify an evidence file without modifying it."""
        target = Path(path)
        try:
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            size = target.stat().st_size
        except OSError as exc:
            return {
                "path": str(target), "verified": False,
                "error": str(exc), "computed_hash": None,
            }
        return {
            "path": str(target), "size": size,
            "expected_hash": expected_hash,
            "computed_hash": digest,
            "verified": bool(expected_hash and digest == expected_hash),
        }