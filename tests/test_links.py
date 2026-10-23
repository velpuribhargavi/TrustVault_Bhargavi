"""Share links: signed, 5 minutes, for one named person who already holds a
live grant, revocable at once. A link never gives access on its own.

The server clock is moved with the ``clock`` fixture; nothing sleeps.
THREATS.md: T13-T17 (links), T66 (forwarded / tampered links).
"""
from __future__ import annotations

import base64
import dataclasses
import json

from conftest import PDF_A, audit_rows
from trustvault.errors import NO_ACCESS_MESSAGE
from trustvault.utils import parse_iso, utcnow


def make_link(world, to="gina", permission="view", owner="alice", doc=None):
    r = world[owner].post(f"/api/documents/{doc or world.doc_a}/links", json={"username": to, "permission": permission})
    assert r.status_code == 201, r.text
    return r.json()


def H(token):
    return {"headers": {"X-Link-Token": token}}


def last_denial_reason(db, who_id):
    rows = [r for r in audit_rows(db, outcome="denied") if r["actor_id"] == who_id]
    return json.loads(rows[-1]["details"])["reason"]


def open_link(world, who, token):
    return world[who].post("/api/links/open", json={"token": token})


def test_link_is_for_one_person_for_five_minutes(world, db):
    link = make_link(world)
    assert link["path"] == f"/#/l/{link['token']}"  # in the fragment: never sent to the server with the page
    assert link["recipient"] == "gina" and link["ttl_seconds"] == 300
    lasts = (parse_iso(link["expires_at"]) - utcnow()).total_seconds()
    assert 295 < lasts <= 300
    created = audit_rows(db, action="link.created", outcome="allowed")[-1]
    d = json.loads(created["details"])
    assert d["recipient"] == "gina" and d["link_id"] == link["link_id"] and created["target_user_id"] == world.ids["gina"]
    assert link["token"] not in created["details"]  # the token itself is never stored


def test_a_link_is_only_for_someone_who_already_has_access(world, db):
    a = world["alice"]
    url = f"/api/documents/{world.doc_a}/links"
    assert a.post(url, json={"username": "frank"}).status_code == 400                         # no grant
    assert a.post(url, json={"username": "erin"}).status_code == 400                          # grant expired
    assert a.post(url, json={"username": "gina", "permission": "download"}).status_code == 400  # above View only
    reasons = [json.loads(r["details"])["reason"] for r in audit_rows(db, action="link.created", outcome="denied")]
    assert reasons == ["no_grant", "no_grant", "link_above_grant"]


def test_recipient_opens_and_reads_through_the_link(world, db):
    link = make_link(world)
    gina = world["gina"]
    r = open_link(world, "gina", link["token"])
    assert r.status_code == 200
    assert r.json()["document_id"] == world.doc_a and r.json()["permission"] == "view"
    doc = gina.get(f"/api/documents/{world.doc_a}", **H(link["token"])).json()
    assert doc["my_permission"] == "view" and doc["access_via"] == "link"
    assert doc["access_expires_at"] == link["expires_at"]  # the link ends before her 30-minute grant
    page = gina.get(f"/api/documents/{world.doc_a}/preview/pages/1", **H(link["token"]))
    assert page.status_code == 200 and page.content.startswith(b"\x89PNG")
    # A view link is view-only: the original file never leaves.
    r = gina.get(f"/api/documents/{world.doc_a}/download", **H(link["token"]))
    assert r.status_code == 403 and PDF_A not in r.content
    assert last_denial_reason(db, world.ids["gina"]) == "view_only"
    opened = audit_rows(db, action="link.opened", outcome="allowed")[-1]
    assert json.loads(opened["details"])["link_id"] == link["link_id"]
    viewed = audit_rows(db, action="document.preview_page", outcome="allowed")[-1]
    assert json.loads(viewed["details"])["via"] == "link" and json.loads(viewed["details"])["link_id"] == link["link_id"]


def test_download_link_hands_out_the_file_and_records_which_link(world, db):
    link = make_link(world, to="carol", permission="download")
    r = world["carol"].get(f"/api/documents/{world.doc_a}/download", **H(link["token"]))
    assert r.status_code == 200 and r.content == PDF_A
    row = audit_rows(db, action="document.download", outcome="allowed")[-1]
    assert json.loads(row["details"])["link_id"] == link["link_id"] and row["actor_id"] == world.ids["carol"]


def test_a_view_link_caps_a_higher_grant(world, db):
    link = make_link(world, to="dave", permission="view")
    assert world["dave"].get(f"/api/documents/{world.doc_a}/download", **H(link["token"])).status_code == 403
    assert last_denial_reason(db, world.ids["dave"]) == "view_only"
    assert world["dave"].get(f"/api/documents/{world.doc_a}/download").status_code == 200  # his own grant, no link


def test_forwarded_link_is_useless_to_anyone_else(world, db):
    link = make_link(world)
    for who in ("bob", "carol", "dave", "admin"):
        r = open_link(world, who, link["token"])
        assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS_MESSAGE, who
    assert last_denial_reason(db, world.ids["bob"]) == "wrong_user"
    assert last_denial_reason(db, world.ids["carol"]) == "wrong_user"  # even though she has her own grant
    assert world["carol"].get(f"/api/documents/{world.doc_a}/preview", **H(link["token"])).status_code == 403
    assert open_link(world, "gina", link["token"]).status_code == 200


def test_link_needs_a_signed_in_recipient(world):
    link = make_link(world)
    assert world.anon().post("/api/links/open", json={"token": link["token"]}).status_code == 401
    assert world.anon().get(f"/api/documents/{world.doc_a}", **H(link["token"])).status_code == 401


def test_link_works_at_4_59_and_fails_at_5_01(world, db, clock):
    link = make_link(world)
    clock.advance(seconds=299)
    assert open_link(world, "gina", link["token"]).status_code == 200
    clock.advance(seconds=2)
    r = open_link(world, "gina", link["token"])
    assert r.status_code == 403 and r.json()["code"] == "no_access"
    assert last_denial_reason(db, world.ids["gina"]) == "link_expired"
    assert world["gina"].get(f"/api/documents/{world.doc_a}/preview", **H(link["token"])).status_code == 403


def test_link_dies_with_the_grant_behind_it(world, db, clock):
    world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                        json={"username": "frank", "permission": "view", "duration_minutes": 1})
    link = make_link(world, to="frank")
    assert open_link(world, "frank", link["token"]).status_code == 200
    clock.advance(seconds=61)  # the grant ends before the 5-minute link would
    assert open_link(world, "frank", link["token"]).status_code == 403
    assert last_denial_reason(db, world.ids["frank"]) == "grant_expired"


def test_revoking_the_recipient_kills_the_link_at_once(world, db):
    link = make_link(world)
    assert open_link(world, "gina", link["token"]).status_code == 200
    world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{world.grant_gina}")
    assert open_link(world, "gina", link["token"]).status_code == 403
    assert last_denial_reason(db, world.ids["gina"]) == "grant_revoked"


def test_revoke_all_kills_every_outstanding_link_at_once(world, db):
    a, b = make_link(world, to="gina"), make_link(world, to="carol")
    assert world["alice"].post(f"/api/documents/{world.doc_a}/links/revoke-all").status_code == 200
    assert open_link(world, "gina", a["token"]).status_code == 403
    assert open_link(world, "carol", b["token"]).status_code == 403
    assert last_denial_reason(db, world.ids["gina"]) == "link_revoked"
    assert audit_rows(db, action="link.revoked_all", outcome="allowed")
    # A new link works again.
    assert open_link(world, "gina", make_link(world)["token"]).status_code == 200


def test_taking_anyone_s_access_away_also_kills_links(world, db):
    link = make_link(world)
    assert open_link(world, "gina", link["token"]).status_code == 200
    world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{world.grant_carol}")  # someone else's grant
    assert open_link(world, "gina", link["token"]).status_code == 403
    assert last_denial_reason(db, world.ids["gina"]) == "link_revoked"
    link = make_link(world)
    world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "dave", "permission": "view"})
    assert open_link(world, "gina", link["token"]).status_code == 403  # lowering a level also kills links


def test_trash_kills_links_and_restore_does_not_bring_them_back(world):
    link = make_link(world)
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    assert open_link(world, "gina", link["token"]).status_code == 403
    world["alice"].post(f"/api/documents/{world.doc_a}/restore")
    assert open_link(world, "gina", link["token"]).status_code == 403


def test_tampered_or_made_up_links_are_refused(world, db):
    link = make_link(world)
    head, body, sig = link["token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["p"] = "download"                       # try to upgrade view -> download
    claims["exp"] += 3600                          # ... and live an hour longer
    forged_body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    for token in (f"{head}.{forged_body}.{sig}", f"{head}.{body}.{sig[:-2]}AA", "v1.e30.AAAA", "x" * 50):
        assert open_link(world, "gina", token).status_code == 403, token
        assert world["gina"].get(f"/api/documents/{world.doc_a}/preview", **H(token)).status_code == 403
    assert last_denial_reason(db, world.ids["gina"]) == "link_invalid"


def test_link_in_the_query_string_is_ignored(world, db):
    """Links are accepted only in the X-Link-Token header, never the URL, so
    they cannot end up in access logs or Referer headers."""
    link = make_link(world)
    doc = world["gina"].get(f"/api/documents/{world.doc_a}?link={link['token']}").json()
    assert doc["access_via"] == "grant"
    assert "link_id" not in audit_rows(db, action="document.view", outcome="allowed")[-1]["details"]


def test_link_cannot_be_used_on_another_document(world, db):
    link = make_link(world, to="carol")
    r = world["carol"].get(f"/api/documents/{world.doc_b}", **H(link["token"]))
    assert r.status_code == 403
    assert last_denial_reason(db, world.ids["carol"]) == "link_wrong_document"


def test_only_the_owner_makes_links_and_never_for_admins_edit_or_inactive(world, db):
    url = f"/api/documents/{world.doc_a}/links"
    for who in ("dave", "carol", "gina", "bob", "admin"):
        assert world[who].post(url, json={"username": "gina"}).status_code == 403, who
    a = world["alice"]
    assert a.post(url, json={"username": "admin"}).status_code == 400
    assert a.post(url, json={"username": "alice"}).status_code == 400
    assert a.post(url, json={"username": "ghost"}).status_code == 404
    assert a.post(url, json={"username": "dave", "permission": "edit"}).status_code == 422
    world["admin"].patch(f"/api/admin/users/{world.ids['carol']}", json={"is_active": False})
    assert a.post(url, json={"username": "carol"}).status_code == 400  # deactivated, though her grant row remains
    reasons = {json.loads(r["details"])["reason"] for r in audit_rows(db, action="link.created", outcome="denied")}
    assert {"target_admin", "target_is_owner", "unknown_user", "target_inactive"} <= reasons


def test_owner_sees_recent_links_and_their_state(world, clock):
    first = make_link(world)
    open_link(world, "gina", first["token"])
    clock.advance(seconds=301)
    make_link(world, to="carol")
    items = {i["link_id"]: i for i in world["alice"].get(f"/api/documents/{world.doc_a}/links").json()["items"]}
    assert items[first["link_id"]]["status"] == "expired" and items[first["link_id"]]["opened"] is True
    world["alice"].post(f"/api/documents/{world.doc_a}/links/revoke-all")
    items = world["alice"].get(f"/api/documents/{world.doc_a}/links").json()["items"]
    assert {i["status"] for i in items} == {"expired", "revoked"}


def test_link_from_an_owner_who_left_dies(world, db):
    link = make_link(world)
    world["admin"].patch(f"/api/admin/users/{world.ids['alice']}", json={"is_active": False})
    assert open_link(world, "gina", link["token"]).status_code == 403
    assert last_denial_reason(db, world.ids["gina"]) == "link_owner_changed"


def test_opening_links_is_rate_limited_per_person_and_audited(world, db):
    world.app.state.ctx.limiter.reset()
    world.app.state.ctx.settings = dataclasses.replace(world.app.state.ctx.settings, link_rate_per_user_per_minute=3)
    for _ in range(3):
        assert open_link(world, "bob", "x" * 40).status_code == 403
    assert open_link(world, "bob", "x" * 40).status_code == 429
    assert json.loads(audit_rows(db, action="link.opened", outcome="denied")[-1]["details"])["reason"] == "rate_limited"
    assert open_link(world, "gina", make_link(world)["token"]).status_code == 200
