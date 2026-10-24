"""Schema upgrades that keep the data (and the audit chain) intact.

Two kinds of step:

* **Structural** (``structural_sql``) - plain SQL that runs in the same
  transaction as ``schema.sql`` when the database is opened:

  - v5 -> v6: ``documents.classification`` (existing documents become
    Internal); the access_requests table comes from ``schema.sql``.
  - v4 -> v5: the ``users.totp_*`` columns for two-step sign-in (new tables
    come from ``schema.sql`` itself).
  - v3 -> v4: ``audit_log.session_ref`` is added (existing rows keep NULL, and
    a NULL session_ref is left out of the hash input, so every existing hash
    still verifies) and the audit indexes are replaced by the four the audit
    page filters on.
  - An ``audit_log`` without hash columns (a table from before the chain
    existed) is renamed to ``audit_log_legacy``; ``schema.sql`` then creates
    the chained, append-only table next to it.

* **Hash backfill** (``import_legacy_audit``) - needs the audit key, so it runs
  once the key ring is loaded. Every legacy row is copied, oldest first, into
  the chained table through the same code path as a live event (hash computed
  in the same transaction as the insert), then the legacy table is dropped.
  Nothing in the chained table is ever updated or deleted.

What a backfill can and cannot prove: from the moment of the backfill on, any
change to those rows is detected. It cannot prove the rows were not edited
*before* the backfill, because nothing protected them then. The migration
event records how many rows were backfilled and when, so an investigator
knows where that boundary is (THREATS.md T73).
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

FIRST_UPGRADABLE_VERSION = 3
LEGACY_TABLE = "audit_log_legacy"
CHAIN_COLUMNS = ("prev_hash", "entry_hash")
# Columns copied from a legacy table when present; missing ones become NULL.
LEGACY_FIELDS = ("ts", "actor_id", "actor_name", "action", "outcome", "document_id", "target_user_id",
                 "ip", "user_agent", "details")
OUTCOMES = {"allowed", "denied", "error", "info"}
SUPERSEDED_INDEXES = ("idx_audit_actor", "idx_audit_action")
# (table, column, type) added after v3, in the order they arrived.
ADDED_COLUMNS = (
    ("audit_log", "session_ref", "TEXT"),          # v4: which sign-in session an event belongs to
    ("users", "totp_secret", "BLOB"),              # v5: two-step sign-in
    ("users", "totp_enabled_at", "TEXT"),
    ("users", "totp_last_step", "INTEGER"),
    ("users", "totp_pending", "BLOB"),
    ("users", "totp_pending_at", "TEXT"),
    ("documents", "classification",                # v6: Public / Internal / Confidential
     "TEXT NOT NULL DEFAULT 'internal' CHECK (classification IN ('public', 'internal', 'confidential'))"),
)


@dataclass
class MigrationReport:
    from_version: int
    to_version: int
    steps: list[str] = field(default_factory=list)
    backfilled_rows: int = 0
    renumbered: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.steps) or self.backfilled_rows > 0

    def details(self) -> dict:
        return {"from_version": self.from_version, "to_version": self.to_version, "steps": self.steps,
                "backfilled_rows": self.backfilled_rows, "renumbered": self.renumbered}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}  # table names are constants here


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None


def structural_sql(conn: sqlite3.Connection, report: MigrationReport) -> str:
    """SQL to run (inside the schema transaction) before schema.sql."""
    sql: list[str] = []
    # Columns added since v3. All nullable, so existing rows are untouched;
    # new tables come from schema.sql (CREATE TABLE IF NOT EXISTS).
    for table, column, kind in ADDED_COLUMNS:
        if table == "audit_log" and not set(CHAIN_COLUMNS) <= _columns(conn, "audit_log"):
            continue  # a pre-chain table is replaced below, with every column
        if _table_exists(conn, table) and column not in _columns(conn, table):
            sql.append(f"ALTER TABLE {table} ADD COLUMN {column} {kind};")  # names from the constant list above
            report.steps.append(f"added {table}.{column}")
    if _table_exists(conn, "audit_log"):
        cols = _columns(conn, "audit_log")
        if not set(CHAIN_COLUMNS) <= cols:
            # A table from before the hash chain. Its indexes and triggers would
            # keep their names after a rename and stop schema.sql from creating
            # the real ones, so drop them first.
            for kind, name in conn.execute("SELECT type, name FROM sqlite_master WHERE tbl_name = 'audit_log' "
                                           "AND type IN ('index', 'trigger') AND sql IS NOT NULL"):
                sql.append(f'DROP {kind.upper()} IF EXISTS "{name}";')
            sql.append(f"ALTER TABLE audit_log RENAME TO {LEGACY_TABLE};")
            report.steps.append("audit table without hashes set aside for backfill")
        existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        for name in SUPERSEDED_INDEXES:
            if name in existing:
                sql.append(f"DROP INDEX IF EXISTS {name};")
                report.steps.append(f"replaced index {name}")
        for name in ("idx_audit_actor_ts", "idx_audit_action_outcome_ts", "idx_audit_session"):
            if name not in existing:
                report.steps.append(f"created index {name}")
    return "\n".join(sql) + ("\n" if sql else "")


def import_legacy_audit(conn: sqlite3.Connection, audit, report: MigrationReport | None = None) -> int:
    """Copy rows of ``audit_log_legacy`` into the chained table, computing each
    hash in the same transaction as its insert, then drop the legacy table.
    Returns the number of rows backfilled (0 when there is nothing to do)."""
    from .db import transaction  # local import: db imports this module

    if not _table_exists(conn, LEGACY_TABLE):
        return 0
    cols = _columns(conn, LEGACY_TABLE)
    order = "seq" if "seq" in cols else "rowid"
    select = ", ".join((f'"{c}"' if c in cols else f"NULL AS {c}") for c in LEGACY_FIELDS)
    seq_col = "seq" if "seq" in cols else "rowid AS seq"
    count = 0
    renumbered = False
    with transaction(conn) as tx:
        if tx.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]:
            raise RuntimeError("audit_log already has entries; refusing to backfill legacy rows in front of them")
        for raw in tx.execute(f"SELECT {seq_col}, {select} FROM {LEGACY_TABLE} ORDER BY {order} ASC").fetchall():
            row = dict(raw)
            count += 1
            renumbered = renumbered or row["seq"] != count
            details = row["details"]
            try:
                json.loads(details) if details else None
            except (TypeError, ValueError):
                details = json.dumps({"legacy_text": str(details)})
            audit.import_entry(tx, {
                "ts": row["ts"] or "1970-01-01T00:00:00.000000Z",
                "actor_id": row["actor_id"], "actor_name": row["actor_name"],
                "action": row["action"] or "legacy.unknown",
                "outcome": row["outcome"] if row["outcome"] in OUTCOMES else "info",
                "document_id": row["document_id"], "target_user_id": row["target_user_id"],
                "ip": row["ip"], "user_agent": row["user_agent"], "details": details or "{}",
            })
        tx.execute(f"DROP TABLE {LEGACY_TABLE}")
    audit.anchor_latest(conn)
    if report is not None:
        report.backfilled_rows = count
        report.renumbered = renumbered
        report.steps.append(f"backfilled hashes for {count} existing audit rows")
    return count
