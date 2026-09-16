"""Simple integration layer for the ULPF application."""

from __future__ import annotations

import os
from typing import Any

from .database import Database
from .raw_store import RawStore
from .repositories import StorageRepository


_repository: StorageRepository | None = None


def get_repository() -> StorageRepository:
    global _repository

    if _repository is None:
        database = Database()

        database.wait_until_ready(
            timeout=int(
                os.getenv("ULPF_DB_READY_TIMEOUT", "60")
            )
        )

        database.initialize()

        raw_store = RawStore(
            os.getenv(
                "ULPF_RAW_STORE",
                "/data/raw",
            )
        )

        _repository = StorageRepository(
            database=database,
            raw_store=raw_store,
        )

    return _repository


def persist_event(
    event: dict[str, Any],
    raw: Any = None,
) -> str:
    return get_repository().save_event(
        event,
        raw=raw,
    )


def persist_alert(alert: dict[str, Any]) -> None:
    get_repository().save_alert(alert)


def persist_agent(agent: dict[str, Any]) -> None:
    get_repository().upsert_agent(agent)


def persist_plugin(plugin: dict[str, Any]) -> None:
    get_repository().upsert_plugin(plugin)