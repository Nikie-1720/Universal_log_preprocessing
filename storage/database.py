"""PostgreSQL connection and schema initialization."""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path

import psycopg


class Database:
    def __init__(self) -> None:
        self.url = os.getenv("DATABASE_URL", "").strip()
        self.host = os.getenv("DATABASE_HOST", "localhost")
        self.port = int(os.getenv("DATABASE_PORT", "5432"))
        self.name = os.getenv("DATABASE_NAME", "ulpf")
        self.user = os.getenv("DATABASE_USER", "ulpf")
        self.password = os.getenv("DATABASE_PASSWORD", "")
        self.sslmode = os.getenv("DATABASE_SSLMODE", "").strip() or None

    def connect(self):
        if self.url:
            kwargs = {"connect_timeout": 5}
            if self.sslmode:
                kwargs["sslmode"] = self.sslmode
            return psycopg.connect(self.url, **kwargs)
        kwargs = {
            "host": self.host, "port": self.port, "dbname": self.name,
            "user": self.user, "connect_timeout": 5,
        }
        # An empty password is allowed only for local peer/trust auth.  Never
        # ship a credential in source or compose defaults.
        if self.password:
            kwargs["password"] = self.password
        if self.sslmode:
            kwargs["sslmode"] = self.sslmode
        return psycopg.connect(**kwargs)

    def wait_until_ready(
        self,
        timeout: int = 60,
        interval: int = 2,
    ) -> None:
        deadline = time.time() + timeout
        last_error = None

        while time.time() < deadline:
            try:
                with self.connect() as conn:
                    conn.execute("SELECT 1")
                return
            except Exception as exc:
                last_error = exc
                time.sleep(interval)

        raise RuntimeError(
            f"PostgreSQL did not become ready: {last_error}"
        )

    def initialize(self) -> None:
        schema_path = Path(__file__).with_name("schema.sql")

        if not schema_path.exists():
            raise FileNotFoundError(
                f"PostgreSQL schema not found: {schema_path}"
            )

        schema = schema_path.read_text(encoding="utf-8")
        migration_dir = schema_path.with_name("migrations")

        with self.connect() as conn:
            # Serialize startup migrations across web workers/containers.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('ulpf-schema'))")
            conn.execute(schema)
            if migration_dir.is_dir():
                for migration_path in sorted(migration_dir.glob("*.sql")):
                    version = migration_path.stem
                    applied = conn.execute(
                        "SELECT 1 FROM schema_migrations WHERE version = %s",
                        (version,),
                    ).fetchone()
                    if applied:
                        continue
                    conn.execute(migration_path.read_text(encoding="utf-8"))
                    conn.execute(
                        "INSERT INTO schema_migrations(version) VALUES (%s) "
                        "ON CONFLICT (version) DO NOTHING",
                        (version,),
                    )
            conn.commit()

    @contextmanager
    def transaction(self):
        with self.connect() as conn:
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise