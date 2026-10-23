"""Requests for access: a person asks, the owner approves (level and duration)
or denies (optional reason), the person sees the status, and all of it is
audited. Asking never reveals whether a document exists. THREATS.md: T82-T84.

In the fixture: bob owns DOC_B and has shared it with nobody; alice owns DOC_A
(carol: download, gina: view, dave: edit, erin: expired).
"""
from __future__ import annotations

import json

from conftest import audit_rows
from trustvault.errors import NO_ACCESS_MESSAGE
from trustvault.routes.access_requests import SENT
from trustvault.utils import parse_iso, utcnow

FAKE = "AAAAAAAAAAAAAAAAAAAAAA"


def ask(client, doc_id, permission="view", note=""):
    return client.post("/api/access-requests", json={"document_id": doc_id, "permission": permission, "note": note})


def mine(client) -> list[dict]:
    r = client.get("/api/access-requests/mine")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def incoming(client) -> list[dict]:
    r = client.get("/api/access-requests/incoming")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_a_viewer_asks_and_the_owner_approves_with_level_and_duration(world, db):
    carol, bob = world["carol"], world["bob"]
    assert carol.get(f"/api/documents/{world.doc_b}").status_code == 403
    r = ask(carol, world.doc_b, "download", "Need the drawing for the site visit")
    assert r.status_code == 202 and r.json()["message"] == SENT
    rid = r.json()["id"]
    pending = mine(carol)[0]
    assert pending["status"] == "pending" and pending["document_name"] is None      # no name before a yes
    waiting = incoming(bob)
    assert [(w["id"], w["requester"]["username"], w["permission"], w["note"]) for w in waiting] == \
        [(rid, "carol", "download", "Need the drawing for the site visit")]
    r = bob.post(f"/api/access-requests/{rid}/approve", json={"permission": "view", "duration_minutes": 120})
    assert r.status_code == 200 and r.json()["grant"]["permission"] == "view"
    assert carol.get(f"/api/documents/{world.doc_b}").status_code == 200
    assert carol.get(f"/api/documents/{world.doc_b}/download").status_code == 403    # the owner chose View only
    done = mine(carol)[0]
    assert done["status"] == "approved" and done["document_name"] == "Bridge drawing rev B.png"
    assert done["granted_permission"] == "view"
    left = (parse_iso(done["grant_expires_at"]) - utcnow()).total_seconds()
    assert 119 * 60 < left <= 120 * 60
    assert incoming(bob) == []
    actions = [r["action"] for r in audit_rows(db, document_id=world.doc_b)]
    start = actions.index("access.requested")
    assert actions[start:start + 3] == ["access.requested", "access.request_approved", "access.granted"]


def test_asking_never_reveals_whether_a_document_exists(world, db):
    carol = world["carol"]
    real, fake = ask(carol, world.doc_b), ask(carol, FAKE)
    assert real.status_code == fake.status_code == 202
    assert {k: v for k, v in real.json().items() if k != "id"} == {k: v for k, v in fake.json().items() if k != "id"}
    assert [(i["status"], i["document_name"]) for i in mine(carol)] == [("pending", None), ("pending", None)]
    # Nobody can act on the made-up one, and no owner sees it.
    for owner in ("alice", "bob", "frank"):
        assert FAKE not in {i["document_id"] for i in incoming(world[owner])}
    fake_row = audit_rows(db, action="access.requested")[-1]
    assert fake_row["document_id"] is None and json.loads(fake_row["details"])["requested_id"] == FAKE
    assert ask(carol, "not a document").status_code == 422


def test_the_owner_can_deny_with_a_reason_the_person_sees(world, db):
    rid = ask(world["carol"], world.doc_b, "edit").json()["id"]
    r = world["bob"].post(f"/api/access-requests/{rid}/deny", json={"reason": "Only the engineering team"})
    assert r.status_code == 200
    item = mine(world["carol"])[0]
    assert item["status"] == "denied" and item["owner_reason"] == "Only the engineering team"
    assert item["document_name"] is None
    assert world["carol"].get(f"/api/documents/{world.doc_b}").status_code == 403
    row = audit_rows(db, action="access.request_denied")[-1]
    assert row["actor_name"] == "bob" and json.loads(row["details"])["owner_note"] == "Only the engineering team"


def test_only_the_documents_owner_can_decide(world, db):
    rid = ask(world["carol"], world.doc_a, "edit").json()["id"]
    grants_before = db.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
    for who, reason in (("bob", "no_grant"), ("carol", "download_cannot_share"), ("dave", "edit_cannot_share"),
                        ("admin", "admin_never_reads_content")):
        for verb in ("approve", "deny"):
            r = world[who].post(f"/api/access-requests/{rid}/{verb}", json={})
            assert r.status_code == 403, (who, verb)
            if who != "admin" or verb != "approve":
                assert r.json() == {"detail": NO_ACCESS_MESSAGE, "code": "no_access"}, (who, verb)
        assert json.loads(audit_rows(db, outcome="denied")[-1]["details"])["reason"] == reason, who
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == grants_before
    assert mine(world["carol"])[0]["status"] == "pending"
    assert world.anon().post(f"/api/access-requests/{rid}/approve", json={}).status_code == 401


def test_a_request_can_be_decided_only_once_and_only_while_pending(world, db):
    rid = ask(world["frank"], world.doc_a).json()["id"]
    assert world["alice"].post(f"/api/access-requests/{rid}/approve", json={}).status_code == 200
    again = world["alice"].post(f"/api/access-requests/{rid}/deny", json={})
    assert again.status_code == 409
    assert json.loads(audit_rows(db, action="access.request_denied")[-1]["details"])["reason"] == "request_not_pending"
    rid2 = ask(world["bob"], world.doc_a).json()["id"]
    assert world["bob"].post(f"/api/access-requests/{rid2}/withdraw").status_code == 200
    assert world["alice"].post(f"/api/access-requests/{rid2}/approve", json={}).status_code == 409
    assert world["bob"].get(f"/api/documents/{world.doc_a}").status_code == 403       # withdrawn: nothing given


def test_unanswered_requests_lapse_after_14_days(world, clock):
    rid = ask(world["carol"], world.doc_b).json()["id"]
    clock.advance(days=14, seconds=1)
    carol, bob = world.fresh("carol"), world.fresh("bob")
    assert mine(carol)[0]["status"] == "expired"
    assert incoming(bob) == []
    assert bob.post(f"/api/access-requests/{rid}/approve", json={}).status_code == 409
    assert ask(carol, world.doc_b).status_code == 202                                 # and can ask again
    assert [i["status"] for i in mine(carol)] == ["pending", "withdrawn"]


def test_administrators_never_ask(world, db):
    r = ask(world["admin"], world.doc_a)
    assert r.status_code == 403
    assert json.loads(audit_rows(db, action="auth.forbidden")[-1]["details"])["reason"] == "role_required"


def test_requests_are_private_to_the_person_who_asked(world):
    rid = ask(world["carol"], world.doc_b, note="private note").json()["id"]
    assert all(i["id"] != rid for i in mine(world["gina"]))
    assert world["gina"].post(f"/api/access-requests/{rid}/withdraw").status_code == 404
    assert mine(world["carol"])[0]["status"] == "pending"
    # Owners see only requests for their own documents.
    assert all(i["id"] != rid for i in incoming(world["alice"]))
    assert world["carol"].get("/api/access-requests/incoming").status_code == 403      # viewers decide nothing


def test_asking_for_access_you_already_have(world, db):
    assert ask(world["carol"], world.doc_a, "view").status_code == 409                 # carol has download
    assert json.loads(audit_rows(db, action="access.requested")[-1]["details"])["reason"] == "already_has_access"
    assert ask(world["carol"], world.doc_a, "edit").status_code == 202                 # asking for more is fine
    assert ask(world["alice"], world.doc_a, "edit").status_code == 409                 # the owner has everything


def test_asking_twice_keeps_one_request(world, db):
    first = ask(world["carol"], world.doc_b).json()["id"]
    assert ask(world["carol"], world.doc_b).json()["id"] == first
    assert db.execute("SELECT COUNT(*) FROM access_requests WHERE status = 'pending'").fetchone()[0] == 1


def test_open_requests_are_limited_and_the_limit_is_audited(world, db):
    ctx = world.app.state.ctx
    ctx.settings = ctx.settings.with_overrides(max_pending_requests=2)
    assert ask(world["carol"], world.doc_b).status_code == 202
    assert ask(world["carol"], "BBBBBBBBBBBBBBBBBBBBBB").status_code == 202
    r = ask(world["carol"], "CCCCCCCCCCCCCCCCCCCCCC")
    assert r.status_code == 429
    assert json.loads(audit_rows(db, action="access.requested")[-1]["details"])["reason"] == "too_many_pending"


def test_approval_follows_the_same_rules_as_giving_access_by_hand(world, db):
    rid = ask(world["carol"], world.doc_b).json()["id"]
    assert world["admin"].patch(f"/api/admin/users/{world.ids['carol']}", json={"is_active": False}).status_code == 200
    r = world["bob"].post(f"/api/access-requests/{rid}/approve", json={})
    assert r.status_code == 400
    row = audit_rows(db, action="access.request_approved")[-1]
    assert row["outcome"] == "denied" and json.loads(row["details"])["reason"] == "target_inactive"
    assert db.execute("SELECT status FROM access_requests WHERE id = ?", (rid,)).fetchone()[0] == "pending"
    too_long = world["bob"].post(f"/api/access-requests/{rid}/approve", json={"duration_minutes": 400 * 24 * 60})
    assert too_long.status_code in (400, 422)


def test_a_confidential_document_defaults_to_view_only_for_one_hour(world):
    bob = world["bob"]
    assert bob.put(f"/api/documents/{world.doc_b}/classification", json={"classification": "confidential"}
                   ).status_code == 200
    rid = ask(world["carol"], world.doc_b, "edit").json()["id"]
    item = incoming(bob)[0]
    assert item["classification"] == "confidential"
    assert item["default_permission"] == "view" and item["default_minutes"] == 60
    grant = bob.post(f"/api/access-requests/{rid}/approve", json={}).json()["grant"]
    assert grant["permission"] == "view"
    left = (parse_iso(grant["expires_at"]) - utcnow()).total_seconds()
    assert 59 * 60 < left <= 60 * 60


def test_access_that_ran_out_can_be_asked_for_again(world):
    ended = world["erin"].get("/api/access-requests/ended").json()["items"]
    assert [(e["id"], e["name"], e["permission"]) for e in ended] == \
        [(world.doc_a, "Salary letter - Carol.pdf", "download")]
    assert world["carol"].get("/api/access-requests/ended").json()["items"] == []     # only your own
    assert ask(world["erin"], world.doc_a, "download").status_code == 202
    assert world["erin"].get("/api/access-requests/ended").json()["items"][0]["request_pending"] is True


def test_the_owner_sees_requests_in_the_documents_activity(world):
    ask(world["gina"], world.doc_a, "download", "For the audit")
    items = world["alice"].get(f"/api/documents/{world.doc_a}/activity").json()["items"]
    assert any(i["action"] == "access.requested" and i["actor_name"] == "gina" for i in items)
