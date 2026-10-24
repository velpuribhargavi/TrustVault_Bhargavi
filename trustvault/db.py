"""SQLite access helpers.

* One connection per request (cheap for SQLite, no shared mutable state).
* WAL journal mode so readers never block the single writer.
* ``transaction()`` uses ``BEGIN IMMEDIATE`` so writes (and in particular the
  audit hash chain, which reads the previous hash and then inserts) are
  serialised across threads and processes.
* Every query in the project uses bound parameters; no SQL is built from
  user input.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from . import migrations

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 6


class SchemaVersionError(RuntimeError):
    pass


def connect(db_path: Path, durable: bool = True) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    # FULL: a committed audit entry survives a power cut. OFF is for tests only.
    conn.execute("PRAGMA synchronous = FULL" if durable else "PRAGMA synchronous = OFF")
    return conn


def init_schema(db_path: Path, durable: bool = True) -> migrations.MigrationReport | None:
    """Create the schema, or upgrade a v3+ database in place (data and audit
    chain kept). Returns what was upgraded, or None for a new database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path, durable=durable)
    try:
        has_tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'users'").fetchone()[0]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if has_tables and version > SCHEMA_VERSION:
            raise SchemaVersionError(
                f"The database at {db_path} was created by a newer TrustVault (schema v{version}; "
                f"this version understands up to v{SCHEMA_VERSION}). Update the code instead.")
        if has_tables and version < migrations.FIRST_UPGRADABLE_VERSION:
            raise SchemaVersionError(
                f"The database at {db_path} was created by an older TrustVault (schema v{version}, "
                f"this version needs v{SCHEMA_VERSION} and can upgrade from v{migrations.FIRST_UPGRADABLE_VERSION}). "
                "Run reset.bat (or: python scripts/init_db.py --reset --seed) to recreate it.")
        conn.execute("PRAGMA journal_mode = WAL")
        report = migrations.MigrationReport(from_version=version, to_version=SCHEMA_VERSION) if has_tables else None
        upgrade = migrations.structural_sql(conn, report) if report else ""
        # One transaction for the upgrade and the whole schema: either all of it
        # applies or none of it does, and it costs one disk sync.
        conn.executescript("BEGIN;\n" + upgrade + SCHEMA_PATH.read_text(encoding="utf-8") + "\nCOMMIT;")
        return report
    finally:
        conn.close()


class Tx:
    """Handle passed to the body of a transaction; collects after-commit hooks."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._after_commit: list[Callable[[], None]] = []

    def after_commit(self, fn: Callable[[], None]) -> None:
        self._after_commit.append(fn)

    def execute(self, sql: str, params=()):  # convenience passthrough
        return self.conn.execute(sql, params)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[Tx]:
    tx = Tx(conn)
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield tx
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    for fn in tx._after_commit:
        try:
            fn()
        except Exception:  # pragma: no cover - after-commit hooks are best effort
            pass


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
