"""Tamper-evident audit trail.

Three independent layers:

1. **Append-only triggers** - SQLite refuses UPDATE/DELETE on ``audit_log``.
   Stops the application and casual SQL; does not stop someone who can edit
   the database file directly.
2. **HMAC hash chain** - each row stores
   ``entry_hash = HMAC-SHA256(audit_key, canonical JSON of seq, ts, actor,
   action, outcome, document, target user, ip, user agent, details,
   session_ref and prev_hash)``; the first row's prev_hash is the genesis
   value (64 zeros). This is the SHA-256 chain of the specification with a
   secret key added: changing, inserting, deleting or re-ordering any row
   breaks every hash after it, and because the key is not in the database,
   someone who can edit the database cannot recompute a valid chain.
3. **External anchors** - after every commit the (seq, hash) of the newest row
   is appended to a file outside the database. Truncating the tail of the log
   (which a chain alone cannot detect) leaves an anchor pointing at a row that
   no longer exists.

``verify()`` checks all three and reports the first broken sequence number.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import KeyRing
from .db import Tx
from .utils import clean_line, now_iso

GENESIS = "0" * 64
_anchor_lock = threading.Lock()


@dataclass
class AuditContext:
    actor_id: str | None
    actor_name: str | None
    ip: str | None
    user_agent: str | None
    session_ref: str | None = None  # security.session_ref(token_hash); None outside a sign-in session


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _entry_fields(row: dict[str, Any]) -> dict[str, Any]:
    """The hashed fields of a row. session_ref (schema v4) is included only
    when set, so rows written before it existed keep their original hash."""
    fields = {
        "seq": row["seq"],
        "ts": row["ts"],
        "actor_id": row["actor_id"],
        "actor_name": row["actor_name"],
        "action": row["action"],
        "outcome": row["outcome"],
        "document_id": row["document_id"],
        "target_user_id": row["target_user_id"],
        "ip": row["ip"],
        "user_agent": row["user_agent"],
        "details": row["details"],
        "prev_hash": row["prev_hash"],
    }
    if row.get("session_ref") is not None:
        fields["session_ref"] = row["session_ref"]
    return fields


class AuditLog:
    def __init__(self, keyring: KeyRing, anchor_path: Path, durable: bool = True):
        self.keyring = keyring
        self.anchor_path = anchor_path
        self.durable = durable

    # ------------------------------------------------------------------ write
    def append(
        self,
        tx: Tx,
        ctx: AuditContext,
        action: str,
        outcome: str,
        *,
        document_id: str | None = None,
        target_user_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int:
        """Append one entry. Must run inside ``db.transaction()`` (BEGIN
        IMMEDIATE), which serialises writers so the chain cannot fork."""
        return self._insert(tx, {
            "ts": now_iso(),
            "actor_id": ctx.actor_id,
            "actor_name": clean_line(ctx.actor_name, 64) if ctx.actor_name else None,
            "action": action,
            "outcome": outcome,
            "document_id": document_id,
            "target_user_id": target_user_id,
            "ip": clean_line(ctx.ip, 64) if ctx.ip else None,
            "user_agent": clean_line(ctx.user_agent, 200) if ctx.user_agent else None,
            "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":"), default=str),
            "session_ref": ctx.session_ref,
        })

    def import_entry(self, tx: Tx, fields: dict[str, Any]) -> int:
        """Chain a row that was recorded before the chain existed (migration
        backfill). Same insert path, same transaction rules as ``append``.
        Only the last imported row needs an external anchor; the migration
        writes it (``anchor_latest``) once the transaction has committed."""
        return self._insert(tx, {**fields, "session_ref": None}, anchor=False)

    def anchor_latest(self, conn) -> None:
        last = conn.execute("SELECT seq, entry_hash, ts FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        if last is not None:
            self._write_anchor(last["seq"], last["entry_hash"], last["ts"])

    def _insert(self, tx: Tx, fields: dict[str, Any], anchor: bool = True) -> int:
        last = tx.execute("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last["seq"] + 1) if last else 1
        row = {**fields, "seq": seq, "prev_hash": last["entry_hash"] if last else GENESIS}
        entry_hash = self.keyring.audit_mac(_canonical(_entry_fields(row)))
        tx.execute(
            """INSERT INTO audit_log (seq, ts, actor_id, actor_name, action, outcome, document_id,
                                      target_user_id, ip, user_agent, details, prev_hash, entry_hash, session_ref)
               VALUES (:seq, :ts, :actor_id, :actor_name, :action, :outcome, :document_id,
                       :target_user_id, :ip, :user_agent, :details, :prev_hash, :entry_hash, :session_ref)""",
            {**row, "entry_hash": entry_hash},
        )
        if anchor:
            tx.after_commit(lambda: self._write_anchor(seq, entry_hash, row["ts"]))
        return seq

    def _write_anchor(self, seq: int, entry_hash: str, ts: str) -> None:
        with _anchor_lock:
            self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.anchor_path, "a", encoding="ascii") as fh:
                fh.write(f"{seq} {entry_hash} {ts}\n")
                fh.flush()
                if self.durable:
                    os.fsync(fh.fileno())

    # ----------------------------------------------------------------- verify
    def verify(self, conn) -> "VerifyResult":
        result = VerifyResult()
        expected_seq = 1
        prev_hash = GENESIS
        hashes: dict[int, str] = {}
        for raw in conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
            row = dict(raw)
            seq = row["seq"]
            if seq != expected_seq:
                result.fail(expected_seq, f"event #{expected_seq} is missing (the next event found is #{seq})")
                break
            if row["prev_hash"] != prev_hash:
                result.fail(seq, f"event #{seq} does not link to event #{seq - 1}")
                break
            if not self._hash_matches(row):
                result.fail(seq, f"event #{seq} has been modified")
                break
            hashes[seq] = row["entry_hash"]
            prev_hash = row["entry_hash"]
            expected_seq += 1
            result.entries_checked += 1
        result.last_seq = expected_seq - 1

        if result.ok:
            for line_no, (seq, anchored_hash) in enumerate(self._read_anchors(), start=1):
                result.anchors_checked += 1
                if seq > result.last_seq:
                    result.fail(result.last_seq + 1, f"event #{result.last_seq + 1} is missing: anchor {line_no} "
                                f"records event #{seq} but the log ends at #{result.last_seq} (log truncated)")
                    break
                if not _hmac_equal(hashes.get(seq, ""), anchored_hash):
                    result.fail(seq, f"event #{seq} does not match its external anchor (log rewritten)")
                    break

        triggers = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'")}
        missing = {"audit_log_no_update", "audit_log_no_delete"} - triggers
        if missing:
            result.warnings.append(f"append-only trigger(s) missing: {', '.join(sorted(missing))}")
        return result

    def _hash_matches(self, row: dict[str, Any]) -> bool:
        return _hmac_equal(self.keyring.audit_mac(_canonical(_entry_fields(row))), row["entry_hash"])

    def check_entry(self, conn, row: dict[str, Any]) -> dict[str, bool]:
        """Quick check of one event for the detail panel: does its hash match
        its content, and does it link to the event before it? (The full chain
        and the external anchors are checked by ``verify``.)"""
        if row["seq"] == 1:
            linked = row["prev_hash"] == GENESIS
        else:
            prev = conn.execute("SELECT entry_hash FROM audit_log WHERE seq = ?", (row["seq"] - 1,)).fetchone()
            linked = prev is not None and _hmac_equal(prev["entry_hash"], row["prev_hash"])
        return {"hash_matches": self._hash_matches(row), "links_to_previous": linked}

    def _read_anchors(self):
        if not self.anchor_path.exists():
            return
        with open(self.anchor_path, "r", encoding="ascii", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    yield int(parts[0]), parts[1]


def _hmac_equal(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


@dataclass
class VerifyResult:
    ok: bool = True
    entries_checked: int = 0
    anchors_checked: int = 0
    last_seq: int = 0
    first_bad_seq: int | None = None
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def fail(self, seq: int, message: str) -> None:
        self.ok = False
        if self.first_bad_seq is None:
            self.first_bad_seq = seq
        self.problems.append(message)

    @property
    def message(self) -> str:
        if self.ok:
            return f"Chain intact ({self.entries_checked} events)"
        return f"Chain broken at event #{self.first_bad_seq}: {self.problems[0]}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "entries_checked": self.entries_checked,
            "anchors_checked": self.anchors_checked,
            "last_seq": self.last_seq,
            "first_bad_seq": self.first_bad_seq,
            "problems": self.problems,
            "warnings": self.warnings,
        }
