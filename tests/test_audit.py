"""You can prove who reached a document - and the record cannot be quietly
altered.  THREATS.md: T34-T39."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from conftest import audit_rows, make_pdf


def verify(world):
    r = world["admin"].get("/api/admin/audit/verify")
    assert r.status_code == 200
    return r.json()


def test_every_required_event_is_recorded(world, db):
    a, c, d = world["alice"], world["carol"], world["dave"]
    c.get(f"/api/documents/{world.doc_a}/download")
    d.patch(f"/api/documents/{world.doc_a}", json={"description": "edited"})
    d.post(f"/api/documents/{world.doc_a}/versions", files={"file": ("v2.pdf", make_pdf(b"2"), "application/pdf")})
    a.delete(f"/api/documents/{world.doc_a}/grants/{world.grant_carol}")
    c.get(f"/api/documents/{world.doc_a}/download")              # refused now
    world["bob"].get(f"/api/documents/{world.doc_a}/download")  # never allowed
    a.delete(f"/api/documents/{world.doc_a}")

    actions = {(r["action"], r["outcome"], r["actor_name"]) for r in audit_rows(db, document_id=world.doc_a)}
    for expected in [
        ("document.upload", "allowed", "alice"),
        ("access.granted", "allowed", "alice"),
        ("document.download", "allowed", "carol"),
        ("document.update", "allowed", "dave"),
        ("document.version_upload", "allowed", "dave"),
        ("access.revoked", "allowed", "alice"),
        ("document.download", "denied", "carol"),
        ("document.download", "denied", "bob"),
        ("document.delete", "allowed", "alice"),
    ]:
        assert expected in actions, f"missing audit event {expected}"
    # Each row carries who/when/where.
    row = audit_rows(db, action="document.download", outcome="allowed")[0]
    assert row["actor_id"] == world.ids["carol"] and row["ts"] and row["ip"]
    assert json.loads(row["details"])["sha256"]  # exactly which bytes were handed out
    # ... and every refusal carries its internal reason (never shown to the caller).
    reasons = {json.loads(r["details"])["reason"] for r in audit_rows(db, document_id=world.doc_a, outcome="denied")}
    assert {"grant_revoked", "no_grant"} <= reasons


def test_chain_verifies_when_untouched(world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    result = verify(world)
    assert result["ok"] is True and result["entries_checked"] > 10 and result["anchors_checked"] > 10


def test_application_cannot_update_or_delete_audit_rows(db, world):
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log WHERE seq = 1")


def _drop_triggers(db):
    db.execute("DROP TRIGGER audit_log_no_update")
    db.execute("DROP TRIGGER audit_log_no_delete")


def test_edited_row_is_detected(db, world):
    """An attacker with write access to the database file drops the triggers
    and rewrites who downloaded the file."""
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    seq = audit_rows(db, action="document.download", outcome="allowed")[0]["seq"]
    _drop_triggers(db)
    db.execute("UPDATE audit_log SET actor_name = 'bob' WHERE seq = ?", (seq,))
    result = verify(world)
    assert result["ok"] is False and result["first_bad_seq"] == seq
    assert any("trigger" in w for w in result["warnings"])
    alerts = world["admin"].get("/api/admin/alerts").json()["items"]
    assert alerts[0]["rule"] == "audit_integrity" and alerts[0]["severity"] == "critical"


def test_rehashed_row_without_the_key_is_detected(db, world):
    """Recomputing the hash with plain SHA-256 (the attacker does not have the
    HMAC key) still fails verification."""
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    row = audit_rows(db, action="document.download", outcome="allowed")[0]
    _drop_triggers(db)
    fake = hashlib.sha256(b"forged" + row["prev_hash"].encode()).hexdigest()
    db.execute("UPDATE audit_log SET actor_name = 'bob', entry_hash = ? WHERE seq = ?", (fake, row["seq"]))
    assert verify(world)["ok"] is False


def test_deleted_middle_row_is_detected(db, world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    seq = audit_rows(db, action="document.download", outcome="allowed")[0]["seq"]
    _drop_triggers(db)
    db.execute("DELETE FROM audit_log WHERE seq = ?", (seq,))
    result = verify(world)
    assert result["ok"] is False and result["first_bad_seq"] == seq


def test_truncated_tail_is_detected_by_external_anchor(db, world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    last = db.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    _drop_triggers(db)
    db.execute("DELETE FROM audit_log WHERE seq > ?", (last - 3,))  # remove the newest 3 rows cleanly
    result = verify(world)
    assert result["ok"] is False
    assert any("truncated" in p for p in result["problems"])


def test_reordered_rows_are_detected(db, world):
    _drop_triggers(db)
    a, b = db.execute("SELECT * FROM audit_log WHERE seq IN (3, 4) ORDER BY seq").fetchall()
    db.execute("UPDATE audit_log SET actor_name = ?, action = ?, details = ? WHERE seq = 3",
               (b["actor_name"], b["action"], b["details"]))
    db.execute("UPDATE audit_log SET actor_name = ?, action = ?, details = ? WHERE seq = 4",
               (a["actor_name"], a["action"], a["details"]))
    assert verify(world)["ok"] is False


def test_verification_itself_is_audited(db, world):
    verify(world)
    assert audit_rows(db, action="audit.verify")


def test_owner_sees_activity_on_own_document_only(world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    items = world["alice"].get(f"/api/documents/{world.doc_a}/activity").json()["items"]
    assert any(i["action"] == "document.download" and i["actor_name"] == "carol" for i in items)
    assert world["carol"].get(f"/api/documents/{world.doc_a}/activity").status_code == 403
    assert world["bob"].get(f"/api/documents/{world.doc_a}/activity").status_code == 403


def test_audit_search_filters(world):
    world["bob"].get(f"/api/documents/{world.doc_a}/download")
    r = world["admin"].get("/api/admin/audit", params={"outcome": "denied", "actor": "bob"}).json()
    assert r["total"] >= 1 and all(i["actor_name"] == "bob" and i["outcome"] == "denied" for i in r["items"])
    r = world["admin"].get("/api/admin/audit", params={"action": "access."}).json()
    assert r["total"] >= 2 and all(i["action"].startswith("access.") for i in r["items"])
    r = world["admin"].get("/api/admin/audit", params={"document_id": world.doc_a, "action": "document.upload"}).json()
    assert r["total"] == 1 and r["items"][0]["document_name"] == "Salary letter - Carol.pdf"


def test_log_injection_is_inert(world, db):
    from conftest import Client
    Client(world.app).login("evil\nadmin <script>alert(1)</script>", "x-password-123")
    row = audit_rows(db, action="auth.login", outcome="denied")[-1]
    assert "\n" not in row["actor_name"]
    assert verify(world)["ok"] is True


def test_only_admins_see_why_a_request_was_refused(world):
    """The owner sees that bob was refused - not why. The reason is admin-only."""
    world["bob"].get(f"/api/documents/{world.doc_a}/download")
    items = world["alice"].get(f"/api/documents/{world.doc_a}/activity").json()["items"]
    refused = [i for i in items if i["outcome"] == "denied" and i["actor_name"] == "bob"]
    assert refused and all("reason" not in i["details"] and "requested_id" not in i["details"] for i in refused)
    admin_view = world["admin"].get("/api/admin/audit", params={"outcome": "denied", "actor": "bob"}).json()["items"]
    assert admin_view[0]["details"]["reason"] == "no_grant"
