"""Schema upgrades keep every row and the audit chain.

* a v3 database (the Phase 1-2 schema) is upgraded to v4 in place at start-up;
* an audit table from before the hash chain gets its hashes backfilled;
* databases that are too old or too new are refused with a clear message.
THREATS.md: T73.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from conftest import Client, create_user
from trustvault.audit import GENESIS, _canonical, _entry_fields
from trustvault.crypto import KeyRing
from trustvault.db import SCHEMA_VERSION, SchemaVersionError, connect
from trustvault.main import create_app

FIXTURES = Path(__file__).with_name("fixtures")
ROOT = Path(__file__).resolve().parent.parent


def v3_database(settings, rows: int = 6) -> list[dict]:
    """A database exactly as Phase 2 left it: schema v3, chained audit rows
    (hashed without session_ref, which did not exist yet) and their anchors."""
    keyring = KeyRing.load(settings.keys_dir, create=True)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.executescript((FIXTURES / "schema_v3.sql").read_text(encoding="utf-8"))
    prev, written = GENESIS, []
    with open(settings.anchor_path, "w", encoding="ascii") as anchors:
        for seq in range(1, rows + 1):
            row = {"seq": seq, "ts": f"2026-10-0{seq}T09:00:00.000000Z", "actor_id": None, "actor_name": "alice",
                   "action": "document.download", "outcome": "allowed", "document_id": "d" * 22,
                   "target_user_id": None, "ip": "10.0.0.5", "user_agent": "Firefox",
                   "details": json.dumps({"n": seq}), "prev_hash": prev}
            row["entry_hash"] = keyring.audit_mac(_canonical(_entry_fields(row)))
            conn.execute("INSERT INTO audit_log VALUES (:seq, :ts, :actor_id, :actor_name, :action, :outcome, "
                         ":document_id, :target_user_id, :ip, :user_agent, :details, :prev_hash, :entry_hash)", row)
            anchors.write(f"{seq} {row['entry_hash']} {row['ts']}\n")
            prev = row["entry_hash"]
            written.append(row)
    conn.commit()
    conn.close()
    return written


def legacy_database(settings) -> list[tuple]:
    """A v3 database whose audit table predates the hash chain: no prev_hash,
    no entry_hash, fewer columns, a gap in the numbering and some odd values."""
    KeyRing.load(settings.keys_dir, create=True)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.executescript((FIXTURES / "schema_v3.sql").read_text(encoding="utf-8"))
    conn.executescript("""
        DROP TABLE audit_log;
        CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, ts TEXT, actor_name TEXT, action TEXT, outcome TEXT,
                                document_id TEXT, ip TEXT, details TEXT);
        CREATE INDEX idx_audit_ts ON audit_log(ts);
    """)
    rows = [(1, "2025-01-01T08:00:00.000000Z", "alice", "auth.login", "allowed", None, "10.0.0.1", '{"mode":"cookie"}'),
            (2, "2025-01-01T08:01:00.000000Z", "alice", "document.upload", "allowed", "x" * 22, "10.0.0.1", "{}"),
            (4, "2025-01-01T08:02:00.000000Z", "bob", "document.download", "denied", "x" * 22, "10.0.0.2",
             '{"reason":"no_grant"}'),
            (5, "2025-01-01T08:03:00.000000Z", "carol", "document.view", "weird", "x" * 22, "10.0.0.3", "not json"),
            (6, "2025-01-01T08:04:00.000000Z", None, "auth.login", "denied", None, "10.0.0.9", None)]
    conn.executemany("INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()
    return rows


def rows_of(settings) -> list[dict]:
    conn = connect(settings.db_path, durable=False)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY seq")]
    finally:
        conn.close()


def test_a_v3_database_is_upgraded_in_place_and_its_chain_still_verifies(settings):
    before = v3_database(settings)
    app = create_app(settings)
    conn = connect(settings.db_path, durable=False)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)")}
    assert "session_ref" in cols
    assert {"totp_secret", "totp_enabled_at", "totp_last_step"} <= {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'backup_codes'").fetchone()
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"idx_audit_ts", "idx_audit_actor_ts", "idx_audit_action_outcome_ts", "idx_audit_doc",
            "idx_audit_session"} <= indexes
    assert not {"idx_audit_actor", "idx_audit_action"} & indexes
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET actor_name = 'x' WHERE seq = 1")
    conn.close()

    after = rows_of(settings)
    for old, new in zip(before, after):
        assert {k: new[k] for k in old} == old and new["session_ref"] is None  # untouched
    migrated = after[len(before)]
    assert migrated["action"] == "audit.migrated" and migrated["prev_hash"] == before[-1]["entry_hash"]
    details = json.loads(migrated["details"])
    assert details["from_version"] == 3 and details["to_version"] == SCHEMA_VERSION and details["backfilled_rows"] == 0
    assert "added audit_log.session_ref" in details["steps"] and "added users.totp_secret" in details["steps"]

    # New events chain onto the old ones, and the whole thing verifies.
    create_user(app, "admin", "admin")
    admin = Client(app)
    assert admin.login("admin").status_code == 200
    result = admin.get("/api/admin/audit/verify").json()
    assert result["ok"] is True and result["entries_checked"] == len(before) + 2
    assert result["anchors_checked"] >= len(before)
    # Starting again is a no-op: no second upgrade event.
    create_app(settings)
    assert sum(r["action"] == "audit.migrated" for r in rows_of(settings)) == 1


def test_an_audit_table_without_hashes_gets_them_backfilled(settings):
    legacy = legacy_database(settings)
    app = create_app(settings)
    after = rows_of(settings)
    assert len(after) == len(legacy) + 1
    for (old_seq, ts, actor, action, outcome, doc, ip, details), new in zip(legacy, after):
        assert (new["ts"], new["actor_name"], new["action"], new["document_id"], new["ip"]) == (ts, actor, action, doc, ip)
    assert [r["seq"] for r in after] == list(range(1, len(after) + 1))       # the gap is closed, in order
    assert after[0]["prev_hash"] == GENESIS
    assert all(b["prev_hash"] == a["entry_hash"] for a, b in zip(after, after[1:]))
    assert after[0]["details"] == '{"mode":"cookie"}'                         # JSON kept byte for byte
    assert json.loads(after[3]["details"]) == {"legacy_text": "not json"}     # text kept, wrapped
    assert after[3]["outcome"] == "info" and after[4]["details"] == "{}"
    migrated = json.loads(after[-1]["details"])
    assert after[-1]["action"] == "audit.migrated"
    assert migrated["backfilled_rows"] == len(legacy) and migrated["renumbered"] is True

    conn = connect(settings.db_path, durable=False)
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'audit_log_legacy'").fetchone() is None
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
    result = app.state.ctx.audit.verify(conn)
    assert result.ok and result.message == f"Chain intact ({len(legacy) + 1} events)" and result.anchors_checked >= 1
    # From now on a change to a backfilled row is caught like any other.
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 2")
    assert app.state.ctx.audit.verify(conn).first_bad_seq == 2
    conn.close()


def test_a_backfill_never_goes_in_front_of_existing_chained_rows(settings):
    """If both tables somehow exist, the backfill refuses instead of re-numbering history."""
    v3_database(settings, rows=2)
    create_app(settings)
    conn = connect(settings.db_path, durable=False)
    conn.execute("CREATE TABLE audit_log_legacy (seq INTEGER PRIMARY KEY, ts TEXT, action TEXT, outcome TEXT)")
    conn.execute("INSERT INTO audit_log_legacy VALUES (1, '2025-01-01T00:00:00Z', 'auth.login', 'allowed')")
    conn.close()
    with pytest.raises(RuntimeError, match="refusing to backfill"):
        create_app(settings)


@pytest.mark.parametrize("version, words", [(2, "reset.bat"), (SCHEMA_VERSION + 1, "newer")])
def test_databases_that_cannot_be_upgraded_are_refused_clearly(settings, version, words):
    v3_database(settings, rows=1)
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"PRAGMA user_version = {version}")
    conn.close()
    with pytest.raises(SchemaVersionError, match=words):
        create_app(settings)


def test_migrate_script_backs_up_upgrades_and_verifies(settings, monkeypatch, capsys):
    v3_database(settings, rows=3)
    monkeypatch.setenv("TRUSTVAULT_INSTANCE_DIR", str(settings.instance_dir))
    monkeypatch.setenv("TRUSTVAULT_ARGON2_MEMORY_KIB", "1024")
    monkeypatch.setenv("TRUSTVAULT_ARGON2_TIME_COST", "1")
    spec = importlib.util.spec_from_file_location("migrate_script", ROOT / "scripts" / "migrate.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert script.main() == 0
    out = capsys.readouterr().out
    assert f"schema v3 -> v{SCHEMA_VERSION}" in out and "Chain intact (4 events)" in out
    backups = list((settings.instance_dir / "backups").glob("*.db"))
    assert len(backups) == 1
    old = sqlite3.connect(backups[0])
    assert old.execute("PRAGMA user_version").fetchone()[0] == 3  # the backup is the database as it was
    old.close()
    assert script.main() == 0 and f"already v{SCHEMA_VERSION}" in capsys.readouterr().out


def test_a_v4_database_gains_two_step_sign_in_and_keeps_its_people(settings):
    """Phase 3 -> Phase 7: users keep their passwords; the new columns start empty."""
    KeyRing.load(settings.keys_dir, create=True)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.executescript((FIXTURES / "schema_v4.sql").read_text(encoding="utf-8"))
    conn.close()
    app = create_app(settings)
    create_user(app, "carol", "viewer")
    assert Client(app).login("carol").status_code == 200
    conn = connect(settings.db_path, durable=False)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    row = conn.execute("SELECT totp_secret, totp_enabled_at FROM users WHERE username = 'carol'").fetchone()
    assert tuple(row) == (None, None)
    steps = json.loads(conn.execute("SELECT details FROM audit_log WHERE action = 'audit.migrated'").fetchone()[0])["steps"]
    assert "added users.totp_secret" in steps and "added audit_log.session_ref" not in steps
    conn.close()


def test_a_v5_database_gets_labels_and_requests_and_keeps_its_documents(settings):
    """Phase 7 -> Phase 4: existing documents become Internal; nothing else changes."""
    KeyRing.load(settings.keys_dir, create=True)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.executescript((FIXTURES / "schema_v5.sql").read_text(encoding="utf-8"))
    conn.execute("INSERT INTO users (id, username, display_name, password_hash, role, created_at, password_changed_at) "
                 "VALUES ('u1', 'olive', 'Olive', 'x', 'owner', '2026-01-01', '2026-01-01')")
    conn.execute("INSERT INTO documents (id, owner_id, name, category, created_at, updated_at) "
                 "VALUES ('d1', 'u1', 'Old memo', 'general', '2026-01-01', '2026-01-01')")
    conn.commit()
    conn.close()
    create_app(settings)
    conn = connect(settings.db_path, durable=False)
    assert conn.execute("SELECT classification FROM documents WHERE id = 'd1'").fetchone()[0] == "internal"
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'access_requests'").fetchone()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE documents SET classification = 'secret' WHERE id = 'd1'")
    steps = json.loads(conn.execute("SELECT details FROM audit_log WHERE action = 'audit.migrated'").fetchone()[0])["steps"]
    assert steps == ["added documents.classification"]
    conn.close()
