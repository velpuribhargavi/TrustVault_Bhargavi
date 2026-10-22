"""Share links: signed, 5 minutes, for one named person, revocable at once.

THREATS.md: T13-T17 (links), T66 (forwarded / tampered links).
"""
from __future__ import annotations

import base64
import json

from conftest import PDF_A, audit_rows
from trustvault.errors import NO_ACCESS_MESSAGE
from trustvault.utils import parse_iso, utcnow


def make_link(world, to="frank", permission="view", owner="alice", doc=None):
    r = world[owner].post(f"/api/documents/{doc or world.doc_a}/links", json={"username": to, "permission": permission})
    assert r.status_code == 201, r.text
    return r.json()


def H(token):
    return {"headers": {"X-Link-Token": token}}


def last_denial_reason(db, who_id):
    rows = [r for r in audit_rows(db, outcome="denied") if r["actor_id"] == who_id]
    return json.loads(rows[-1]["details"])["reason"]


def test_link_is_for_one_person_for_five_minutes(world, db):
    link = make_link(world)
    assert link["path"] == f"/#/l/{link['token']}"  # in the fragment: never sent to the server with the page
    assert link["recipient"] == "frank" and link["ttl_seconds"] == 300
    lasts = (parse_iso(link["expires_at"]) - utcnow()).total_seconds()
    assert 295 < lasts <= 300
    created = audit_rows(db, action="link.created", outcome="allowed")[-1]
    d = json.loads(created["details"])
    assert d["recipient"] == "frank" and d["link_id"] == link["link_id"] and created["target_user_id"] == world.ids["frank"]
    assert link["token"] not in created["details"]  # the token itself is never stored


def test_recipient_opens_and_reads_through_the_link(world, db):
    link = make_link(world)
    frank = world["frank"]
    assert frank.get(f"/api/documents/{world.doc_a}").status_code == 403          # no grant of his own
    r = frank.post("/api/links/open", json={"token": link["token"]})
    assert r.status_code == 200
    assert r.json()["document_id"] == world.doc_a and r.json()["permission"] == "view"
    doc = frank.get(f"/api/documents/{world.doc_a}", **H(link["token"])).json()
    assert doc["my_permission"] == "view" and doc["access_via"] == "link" and doc["access_expires_at"]
    page = frank.get(f"/api/documents/{world.doc_a}/preview/pages/1", **H(link["token"]))
    assert page.status_code == 200 and page.content.startswith(b"\x89PNG")
    # A view link is view-only: the original file never leaves.
    r = frank.get(f"/api/documents/{world.doc_a}/download", **H(link["token"]))
    assert r.status_code == 403 and PDF_A not in r.content
    assert last_denial_reason(db, world.ids["frank"]) == "view_cannot_download"
    opened = audit_rows(db, action="link.opened", outcome="allowed")[-1]
    assert json.loads(opened["details"])["link_id"] == link["link_id"]
    viewed = audit_rows(db, action="document.preview_page", outcome="allowed")[-1]
    assert json.loads(viewed["details"])["via"] == "link" and json.loads(viewed["details"])["link_id"] == link["link_id"]


def test_download_link_hands_out_the_file_and_records_which_link(world, db):
    link = make_link(world, permission="download")
    r = world["frank"].get(f"/api/documents/{world.doc_a}/download", **H(link["token"]))
    assert r.status_code == 200 and r.content == PDF_A
    row = audit_rows(db, action="document.download", outcome="allowed")[-1]
    assert json.loads(row["details"])["link_id"] == link["link_id"] and row["actor_id"] == world.ids["frank"]


def test_forwarded_link_is_useless_to_anyone_else(world, db):
    link = make_link(world)
    for who in ("bob", "carol", "gina", "admin"):
        r = world[who].post("/api/links/open", json={"token": link["token"]})
        assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS_MESSAGE, who
    assert last_denial_reason(db, world.ids["bob"]) == "link_wrong_recipient"
    r = world["bob"].get(f"/api/documents/{world.doc_a}/preview", **H(link["token"]))
    assert r.status_code == 403
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 200


def test_link_needs_a_signed_in_recipient(world):
    link = make_link(world)
    assert world.anon().post("/api/links/open", json={"token": link["token"]}).status_code == 401
    assert world.anon().get(f"/api/documents/{world.doc_a}", **H(link["token"])).status_code == 401


def test_link_expires_after_five_minutes(world, db, clock):
    link = make_link(world)
    frank = world["frank"]
    clock.advance(seconds=295)
    assert frank.post("/api/links/open", json={"token": link["token"]}).status_code == 200
    clock.advance(seconds=6)
    r = frank.post("/api/links/open", json={"token": link["token"]})
    assert r.status_code == 403 and r.json()["code"] == "no_access"
    assert last_denial_reason(db, world.ids["frank"]) == "link_expired"
    assert frank.get(f"/api/documents/{world.doc_a}/preview", **H(link["token"])).status_code == 403


def test_revoke_all_kills_every_outstanding_link_at_once(world, db):
    a, b = make_link(world, to="frank"), make_link(world, to="bob")
    assert world["alice"].post(f"/api/documents/{world.doc_a}/links/revoke-all").status_code == 200
    assert world["frank"].post("/api/links/open", json={"token": a["token"]}).status_code == 403
    assert world["bob"].post("/api/links/open", json={"token": b["token"]}).status_code == 403
    assert last_denial_reason(db, world.ids["frank"]) == "link_revoked"
    assert audit_rows(db, action="link.revoked_all", outcome="allowed")
    # A new link works again.
    assert world["frank"].post("/api/links/open", json={"token": make_link(world)["token"]}).status_code == 200


def test_taking_any_access_away_also_kills_links(world):
    link = make_link(world)
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 200
    world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{world.grant_gina}")  # someone else's grant
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 403
    link = make_link(world)
    world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "carol", "permission": "view"})
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 403  # lowered level


def test_trash_kills_links_and_restore_does_not_bring_them_back(world):
    link = make_link(world)
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 403
    world["alice"].post(f"/api/documents/{world.doc_a}/restore")
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 403


def test_tampered_or_made_up_links_are_refused(world, db):
    link = make_link(world)
    head, body, sig = link["token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["p"] = "download"                       # try to upgrade view -> download
    claims["exp"] += 3600                          # ... and live an hour longer
    forged_body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    for token in (f"{head}.{forged_body}.{sig}", f"{head}.{body}.{sig[:-2]}AA", "v1.e30.AAAA", "x" * 50):
        r = world["frank"].post("/api/links/open", json={"token": token})
        assert r.status_code == 403, token
        assert world["frank"].get(f"/api/documents/{world.doc_a}/download", **H(token)).status_code == 403
    assert last_denial_reason(db, world.ids["frank"]) == "link_invalid"


def test_link_in_the_query_string_is_ignored(world):
    """Links are accepted only in the X-Link-Token header, never the URL, so
    they cannot end up in access logs or Referer headers."""
    link = make_link(world)
    assert world["frank"].get(f"/api/documents/{world.doc_a}?link={link['token']}").status_code == 403


def test_link_cannot_be_used_on_another_document(world, db):
    link = make_link(world)
    r = world["frank"].get(f"/api/documents/{world.doc_b}", **H(link["token"]))
    assert r.status_code == 403
    assert last_denial_reason(db, world.ids["frank"]) == "link_wrong_document"


def test_only_the_owner_makes_links_and_never_for_admins_or_edit(world, db):
    url = f"/api/documents/{world.doc_a}/links"
    for who in ("dave", "carol", "gina", "bob", "admin"):
        assert world[who].post(url, json={"username": "frank"}).status_code == 403, who
    a = world["alice"]
    assert a.post(url, json={"username": "admin"}).status_code == 400
    assert a.post(url, json={"username": "alice"}).status_code == 400
    assert a.post(url, json={"username": "ghost"}).status_code == 404
    assert a.post(url, json={"username": "frank", "permission": "edit"}).status_code == 422
    world["admin"].patch(f"/api/admin/users/{world.ids['frank']}", json={"is_active": False})
    assert a.post(url, json={"username": "frank"}).status_code == 400
    reasons = {json.loads(r["details"])["reason"] for r in audit_rows(db, action="link.created", outcome="denied")}
    assert {"target_admin", "target_is_owner", "unknown_user", "target_inactive"} <= reasons


def test_owner_sees_recent_links_and_their_state(world, clock):
    first = make_link(world)
    world["frank"].post("/api/links/open", json={"token": first["token"]})
    clock.advance(seconds=301)
    make_link(world, to="bob")
    items = {i["link_id"]: i for i in world["alice"].get(f"/api/documents/{world.doc_a}/links").json()["items"]}
    assert items[first["link_id"]]["status"] == "expired" and items[first["link_id"]]["opened"] is True
    world["alice"].post(f"/api/documents/{world.doc_a}/links/revoke-all")
    items = world["alice"].get(f"/api/documents/{world.doc_a}/links").json()["items"]
    assert {i["status"] for i in items} == {"expired", "revoked"}


def test_link_from_an_owner_who_left_dies(world):
    link = make_link(world)
    world["admin"].patch(f"/api/admin/users/{world.ids['alice']}", json={"is_active": False})
    assert world["frank"].post("/api/links/open", json={"token": link["token"]}).status_code == 403


def test_opening_links_is_rate_limited_per_person_and_audited(world, db):
    world.app.state.ctx.limiter.reset()
    import dataclasses
    world.app.state.ctx.settings = dataclasses.replace(world.app.state.ctx.settings, link_rate_per_user_per_minute=3)
    for _ in range(3):
        assert world["bob"].post("/api/links/open", json={"token": "x" * 40}).status_code == 403
    assert world["bob"].post("/api/links/open", json={"token": "x" * 40}).status_code == 429
    assert json.loads(audit_rows(db, action="link.opened", outcome="denied")[-1]["details"])["reason"] == "rate_limited"
    assert world["frank"].post("/api/links/open", json={"token": make_link(world)["token"]}).status_code == 200
